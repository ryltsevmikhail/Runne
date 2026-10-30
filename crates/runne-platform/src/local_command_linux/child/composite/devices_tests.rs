use super::*;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

#[test]
fn private_devices_keep_held_character_device_identity() {
    if std::env::var_os("RUNNE_PRIVATE_DEVICE_TEST_CHILD").is_some() {
        assert_eq!(
            unsafe { libc::getpid() },
            1,
            "test must run inside a fresh PID namespace"
        );
        assert_eq!(unsafe { libc::getuid() }, 0, "mapped test namespace root");
        let inherited = std::env::var("RUNNE_PRIVATE_DEVICE_FDS").unwrap();
        let fds: Vec<i32> = inherited.split(',').map(|s| s.parse().unwrap()).collect();
        assert_eq!(fds.len(), 5);
        let expected = std::fs::metadata(format!("/proc/self/fd/{}", fds[0])).unwrap();
        let targets: Vec<_> = ["null", "zero", "full", "random", "urandom"]
            .into_iter()
            .map(|name| CString::new(format!("/dev/{name}")).unwrap())
            .collect();
        let sources: Vec<_> = fds
            .iter()
            .map(|fd| CString::new(format!("/proc/self/fd/{fd}")).unwrap())
            .collect();
        let targets = targets.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        let sources = sources.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        assert_eq!(unsafe { mount_private(&targets, &sources) }, 0);
        let actual = std::fs::metadata("/dev/null").unwrap();
        assert!(actual.file_type().is_char_device());
        assert_eq!(
            (actual.dev(), actual.ino(), actual.rdev()),
            (expected.dev(), expected.ino(), expected.rdev())
        );
        use std::io::{Read, Write};
        assert_eq!(
            File::open("/dev/null").unwrap().read(&mut [0; 1]).unwrap(),
            0
        );
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap()
            .write_all(b"synthetic")
            .unwrap();
        return;
    }
    let module = module_path!().split_once("::").unwrap().1;
    let test = format!("{module}::private_devices_keep_held_character_device_identity");
    // These file descriptions must originate before the mount/user namespace,
    // matching the real multi-threaded daemon's prepared helper.
    let devices = SafeDevices::open().unwrap();
    let mut descriptors = Vec::new();
    devices.child_descriptors(&mut descriptors).unwrap();
    for fd in &descriptors {
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    }
    let inherited = descriptors
        .iter()
        .map(|fd| fd.as_raw_fd().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let output = std::process::Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--test-threads=1", "--nocapture"])
        .env_clear()
        .env("RUNNE_PRIVATE_DEVICE_TEST_CHILD", "1")
        .env("RUNNE_PRIVATE_DEVICE_FDS", inherited)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native device regression: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

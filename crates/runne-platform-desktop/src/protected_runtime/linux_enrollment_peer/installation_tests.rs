use super::*;
use runne_api::provider_credential_enrollment::linux_activation_policy::LinuxInstallationLayout;
use std::time::{Duration, Instant};

/// `Command::spawn` returns after fork, before the child's `execve` completes:
/// reads of `/proc/<pid>/exe` can still observe the pre-exec image, and a
/// transient writer on the freshly copied executable fails `execve` with
/// `ETXTBSY`. Seed the child, wait until its image resolves to the staged
/// path, and retry a busy spawn instead of failing the fixture.
fn spawn_seeded_child(image: &Path) -> (std::process::Child, PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let child = match std::process::Command::new(image).arg("60").spawn() {
            Ok(child) => child,
            Err(error) if error.raw_os_error() == Some(26) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) => panic!("spawn {image:?} failed: {error}"),
        };
        let pid_image = PathBuf::from(format!("/proc/{}/exe", child.id()));
        while Instant::now() < deadline {
            if std::fs::canonicalize(&pid_image).is_ok_and(|resolved| resolved == image) {
                return (child, pid_image);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        return (child, pid_image);
    }
}

#[test]
fn staged_daemon_facts_use_the_signed_desktop_package_writer() {
    use sha2::{Digest as _, Sha256};

    let directory = tempfile::tempdir().unwrap();
    let package = directory.path().join("package/MacOS");
    let stage = directory
        .path()
        .join("runtime/.desktop-protected-activation/executables-v1");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    let desktop = package.join("runne-desktop");
    let package_writer = package.join("runne");
    let packaged_daemon = package.join("runned");
    let staged_daemon = stage.join("signed-daemon.runned");
    let staged_writer = stage.join("signed-writer.runned");
    let staged_writer_alias = stage.join("runne");
    let machine = directory.path().join("machine-id");
    std::fs::copy("/bin/sleep", &desktop).unwrap();
    std::fs::write(&package_writer, b"signed package writer").unwrap();
    std::fs::copy("/bin/sleep", &packaged_daemon).unwrap();
    std::fs::copy(&packaged_daemon, &staged_daemon).unwrap();
    std::fs::write(&staged_writer, b"different staged writer").unwrap();
    std::os::unix::fs::symlink(&staged_writer, &staged_writer_alias).unwrap();
    std::fs::write(&machine, b"test machine").unwrap();

    let (mut desktop_process, desktop_image) = spawn_seeded_child(&desktop);
    let (mut daemon_process, daemon_image) = spawn_seeded_child(&staged_daemon);
    let writer = package_writer_for_desktop(&desktop_image).unwrap();
    assert_eq!(writer, package_writer);
    let facts = LinuxInstallationLayout {
        runtime_root: directory.path(),
        desktop_image: &desktop_image,
        writer_image: &writer,
        daemon_image: &daemon_image,
        machine_id_path: &machine,
    }
    .canonicalize_facts([7; 16])
    .unwrap();
    let expected_writer: [u8; 32] = Sha256::digest(b"signed package writer").into();
    let expected_daemon: [u8; 32] = Sha256::digest(std::fs::read(&packaged_daemon).unwrap()).into();
    let staged_writer: [u8; 32] = Sha256::digest(b"different staged writer").into();
    assert_eq!(facts.writer_image_digest, expected_writer);
    assert_eq!(facts.daemon_image_digest, expected_daemon);
    assert_ne!(facts.writer_image_digest, staged_writer);
    desktop_process.kill().unwrap();
    desktop_process.wait().unwrap();
    daemon_process.kill().unwrap();
    daemon_process.wait().unwrap();
}

#[test]
fn package_writer_resolution_rejects_missing_or_substituted_writer_and_peer_image() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let package = directory.path().join("package/MacOS");
    std::fs::create_dir_all(&package).unwrap();
    let desktop = package.join("runne-desktop");
    std::fs::write(&desktop, b"desktop").unwrap();
    assert!(package_writer_for_desktop(&desktop).is_none());

    let wrong = directory.path().join("wrong-writer");
    std::fs::write(&wrong, b"writer outside authenticated package").unwrap();
    symlink(&wrong, package.join("runne")).unwrap();
    assert!(package_writer_for_desktop(&desktop).is_none());

    std::fs::remove_file(package.join("runne")).unwrap();
    std::fs::write(package.join("runne"), b"replacement package writer").unwrap();
    assert!(package_writer_for_desktop(&directory.path().join("absent/runne-desktop")).is_none());
}

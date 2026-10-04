use super::*;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd};

#[test]
fn landlock_workspace_and_seccomp_block_escape_and_cgroup_controls() {
    let Some((_root, area, identity_bytes)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: landlock_workspace_and_seccomp_block_escape_and_cgroup_controls");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell executable");
    let snapshot =
        runne_platform::local_command_linux::SealedExecutableSnapshot::from_held_file(&exe)
            .expect("sealed shell snapshot");
    let outside = workspace.0.with_extension("synthetic-outside");
    std::fs::write(&outside, "not secret test sentinel").expect("synthetic sentinel");
    let cgroup_fd_path = scope()
        .expect("scope")
        .join(format!("runne-{}", hex48(&identity_bytes)))
        .join("cgroup.procs");
    let mut inherited = Some(match OpenOptions::new().write(true).open(&cgroup_fd_path) {
        Ok(fd) => fd,
        Err(_) => {
            eprintln!("SKIP: private cgroup.procs write descriptor unavailable");
            area.remove();
            return;
        }
    });
    let inherited_number = unsafe {
        libc::fcntl(
            inherited.as_ref().expect("cgroup descriptor").as_raw_fd(),
            libc::F_DUPFD,
            1000,
        )
    };
    assert!(inherited_number >= 1000, "duplicate cgroup descriptor");
    assert_eq!(
        unsafe { libc::fcntl(inherited_number, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0,
        "fixture descriptor must survive exec unless the gate closes it"
    );
    let mut inherited_high = Some(unsafe { File::from_raw_fd(inherited_number) });
    let python = if Path::new("/usr/bin/python3").is_file() {
        "/usr/bin/python3"
    } else if Path::new("/bin/python3").is_file() {
        "/bin/python3"
    } else {
        eprintln!("SKIP: Python syscall fixture unavailable");
        drop(inherited_high.take());
        std::fs::remove_file(&outside).expect("remove sentinel");
        area.remove();
        return;
    };
    let script = OsString::from(format!(
        r#"printf stdout || exit 36; printf stderr >&2 || exit 37; printf ok > '{}/write-ok'; if read x < '{}'; then exit 31; fi; if printf '%s\n' "$$" > '{}'; then exit 32; fi; {} -c 'import ctypes,errno,os; c=ctypes.CDLL(None,use_errno=True); assert c.prctl(39,0,0,0,0)==1; assert c.prctl(21,0,0,0,0)==2; assert c.unshare(0)==-1 and ctypes.get_errno()==errno.EPERM; ctypes.set_errno(0); assert c.mount(None,None,None,0,None)==-1 and ctypes.get_errno()==errno.EPERM; fd=int(os.environ["X2_CGROUP_FD"]); exec("try:\n os.write(fd,b\"x\")\nexcept OSError as e:\n assert e.errno==errno.EBADF\nelse:\n raise AssertionError(\"inherited cgroup FD was writable\")")' || exit 38; exit 0"#,
        workspace.0.display(),
        outside.display(),
        cgroup_fd_path.display(),
        python
    ));
    let env = vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (
            OsString::from("X2_CGROUP_FD"),
            OsString::from(inherited_number.to_string()),
        ),
    ];
    for (label, executable) in [
        (
            "held-file",
            runne_platform::local_command_linux::LinuxCommandExecutable::HeldFile(&exe),
        ),
        (
            "sealed-snapshot",
            runne_platform::local_command_linux::LinuxCommandExecutable::SealedSnapshot(&snapshot),
        ),
    ] {
        eprintln!("RUN: confinement-probe-{label}");
        let command = LinuxCommandSpec {
            executable,
            workspace: &workspace_fd,
            cwd: &cwd,
            argv: vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                script.clone(),
            ],
            env: env.clone(),
        };
        let mut child = command.spawn_gated(&area).expect("protected gate setup");
        child.release().expect("release after test admission");
        assert_eq!(child.wait(Duration::from_secs(10)).expect("leader exit"), 0);
        assert!(!area.is_populated().expect("no command descendants"));
    }
    drop(inherited.take());
    drop(inherited_high.take());
    assert_eq!(
        std::fs::read(workspace.0.join("write-ok")).expect("workspace write"),
        b"ok"
    );
    assert!(
        !workspace.0.join("leak").exists(),
        "outside synthetic sentinel was unreadable"
    );
    std::fs::remove_file(outside).expect("remove sentinel");
    area.remove();
}

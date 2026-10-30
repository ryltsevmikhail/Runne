use super::*;
#[test]
fn coding_command_rebinds_parent_namespace_cwd_without_shell_warning() {
    const FLAG: &str = "RUNNE_CODING_CWD_TEST_FD";
    if let Ok(raw) = std::env::var(FLAG) {
        let root = unsafe { File::from_raw_fd(raw.parse().unwrap()) };
        let expected = std::env::var("RUNNE_CODING_CWD_TEST_PATH").unwrap();
        restrict_parent_traversal(&root);
        let args = coding_arguments::parse(
            "workspace.command.run",
            &serde_json::json!({
                "cwd":".","argv":["/bin/sh","-c","pwd -P"],"timeout_ms":1000
            }),
        )
        .unwrap();
        let output: serde_json::Value =
            serde_json::from_slice(&run(&root, &args).unwrap()).unwrap();
        assert_eq!(output["exit_code"], 0);
        assert_eq!(
            STANDARD
                .decode(output["stderr_base64"].as_str().unwrap())
                .unwrap(),
            b""
        );
        assert_eq!(
            STANDARD
                .decode(output["stdout_base64"].as_str().unwrap())
                .unwrap(),
            format!("{expected}\n").as_bytes()
        );
        return;
    }
    let dir = std::env::temp_dir().join(format!("runne cwd-настройка-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let root = File::open(&dir).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(root.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let test = format!(
        "{}::coding_command_rebinds_parent_namespace_cwd_without_shell_warning",
        module_path!().split_once("::").unwrap().1
    );
    let result = Command::new("/usr/bin/unshare")
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
        .env(FLAG, root.as_raw_fd().to_string())
        .env("RUNNE_CODING_CWD_TEST_PATH", &dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        result.status.success(),
        "native cwd regression: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

// The native helper permits workspace contents and executable system files,
// but deliberately does not permit reading workspace ancestors.
fn restrict_parent_traversal(root: &File) {
    #[repr(C, packed)]
    struct Rule {
        access: u64,
        parent: i32,
    }
    let handled = 1u64 | (1 << 2) | (1 << 3);
    let fd =
        unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &handled, 8usize, 0u32) } as i32;
    assert!(fd >= 0);
    let ruleset = unsafe { File::from_raw_fd(fd) };
    for path in [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/dev/null",
        "/etc/ld.so.cache",
    ] {
        if let Ok(file) = File::open(path) {
            let access = if file.metadata().unwrap().is_dir() {
                handled
            } else {
                1 << 2
            };
            let rule = Rule {
                access,
                parent: file.as_raw_fd(),
            };
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_landlock_add_rule,
                        ruleset.as_raw_fd(),
                        1u32,
                        &rule,
                        0u32,
                    )
                },
                0
            );
        }
    }
    let rule = Rule {
        access: handled,
        parent: root.as_raw_fd(),
    };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1u32,
                &rule,
                0u32,
            )
        },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) },
        0
    );
}

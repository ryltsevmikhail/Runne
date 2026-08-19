#[cfg(unix)]
#[test]
fn created_write_api_consumes_the_one_shot_handle() {
    let source = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/broker/fs/writes.rs"),
    )
    .unwrap();

    assert!(source.contains("handle: CreatedFsHandle"));
    assert!(!source.contains("handle: &CreatedFsHandle"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn created_stage_cannot_be_substituted_before_publication() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let final_path = workspace_root.canonical_path.join("created.txt");
    let Some(created) = create_or_skip_unsupported_tmpfile(&broker, &root, "created.txt") else {
        return;
    };
    if let Some(stage) = directory_entry_names(&workspace_root.canonical_path)
        .into_iter()
        .find(|entry| entry.starts_with(".runne-fs-"))
    {
        let attacker = workspace_root.canonical_path.join("attacker.txt");
        fs::write(&attacker, b"attacker").unwrap();
        fs::rename(attacker, workspace_root.canonical_path.join(stage)).unwrap();
    }

    let result = broker.write_created(created, b"replacement");

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(fs::read(final_path).unwrap(), b"replacement");
    assert_eq!(
        directory_entry_names(&workspace_root.canonical_path),
        ["created.txt"]
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn created_write_failure_never_publishes_the_final_name() {
    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let final_path = workspace_root.canonical_path.join("created.txt");
    let Some(created) = create_or_skip_unsupported_tmpfile(&broker, &root, "created.txt") else {
        return;
    };
    assert!(!final_path.exists());
    crate::broker::fs_unix::fail_next_commit_for_test();

    let result = broker.write_created(created, b"replacement");

    assert!(matches!(result, Err(FsBrokerError::Io(_))));
    assert!(!final_path.exists());
    assert!(directory_entry_names(&workspace_root.canonical_path).is_empty());
}

// This adversarial test is gated to Linux/Android because both of its
// non-regular-file fixtures behave differently on macOS:
// 1. The FIFO is created via rustix `mkfifoat`, which is Linux/Android-only
//    (`mkfifoat`/`mknodat` are gated out on `apple`). macOS has no portable
//    safe `mkfifo` in rustix, and the workspace forbids `unsafe`, so a raw
//    `libc::mkfifo` is not an option.
// 2. On macOS, `openat` on a socket returns `EOPNOTSUPP`, which
//    `map_open_error` does not map to `FsBrokerError::PermissionDenied`
//    (only `NXIO` is mapped), so the socket assertion would fail with
//    `FsBrokerError::Io` instead of `PermissionDenied`.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn resolve_rejects_fifo_and_socket_without_opening_a_blocking_stream() {
    use std::os::unix::net::UnixListener;

    let broker = test_broker();
    let root = broker.open_root("ws1").unwrap();
    let workspace_root = broker.find_root("ws1").unwrap();
    let directory = rustix::fs::open(
        &workspace_root.canonical_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::mkfifoat(&directory, "pipe", rustix::fs::Mode::from_raw_mode(0o600)).unwrap();
    let socket = UnixListener::bind(workspace_root.canonical_path.join("socket")).unwrap();

    assert!(matches!(
        broker.resolve(&root, &CanonicalPath::new("pipe").unwrap()),
        Err(FsBrokerError::PermissionDenied)
    ));
    let socket_result = broker.resolve(&root, &CanonicalPath::new("socket").unwrap());
    assert!(
        matches!(socket_result, Err(FsBrokerError::PermissionDenied)),
        "{socket_result:?}"
    );
    drop(socket);
}

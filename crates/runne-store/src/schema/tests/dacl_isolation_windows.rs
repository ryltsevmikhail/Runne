// Windows isolation regression: the identity guard's DACL writes must stay
// inside the test-owned fixture, never escape to a shared parent.
//
// Layout: the fixture tempdir is created with `tempdir_in` under a disposable
// sentinel base in the workspace target directory — deliberately NOT the
// shared user TEMP, which is never an experimental object here. The database
// nests one more level (`runne-daemon/`), so the guard's runtime root is the
// fixture tempdir and its daemon directory is the deeper level.
//
// The detector is self-validating: a canary subdirectory is deliberately
// restricted through the same `secure_dir_permissions` the guard uses, and
// the snapshot comparison must see that change — then the sentinel base
// itself must be byte-identical across the real store scenario.

#[cfg(windows)]
fn save_dacl(directory: &std::path::Path, file: &std::path::Path) -> Vec<u8> {
    let _ = std::fs::remove_file(file);
    let status = std::process::Command::new("icacls")
        .arg(directory)
        .args(["/save", &file.to_string_lossy()])
        .status()
        .expect("icacls is available on Windows runners");
    assert!(status.success(), "icacls /save failed for {directory:?}");
    std::fs::read(file).expect("icacls /save output")
}

#[cfg(windows)]
#[test]
fn guard_dacl_writes_stay_inside_the_test_owned_fixture() {
    use std::path::PathBuf;

    let workspace_target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .components()
        .collect::<PathBuf>();
    let base: PathBuf = workspace_target.join("dacl-sentinel");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("sentinel base");

    // Detector sensitivity: restricting our own canary must be visible.
    let canary = base.join("canary");
    std::fs::create_dir(&canary).unwrap();
    let canary_before = save_dacl(&canary, &workspace_target.join("dacl-canary-before.txt"));
    secure_dir_permissions(&canary).expect("canary restriction");
    let canary_after = save_dacl(&canary, &workspace_target.join("dacl-canary-after.txt"));
    assert_ne!(
        canary_before, canary_after,
        "detector insensitive: restricting a directory did not change its saved DACL"
    );

    // The real scenario, inside a fixture tempdir under the sentinel base:
    // runtime root = fixture tempdir, daemon directory = one level deeper.
    let fixture = tempfile::tempdir_in(&base).expect("fixture tempdir inside sentinel base");
    let daemon = fixture.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");
    let base_before = save_dacl(&base, &workspace_target.join("dacl-sentinel-before.txt"));

    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer
        .execute_batch("INSERT INTO _daemon_info (key, value) VALUES ('probe-isolation', 'one');")
        .unwrap();
    drop(writer);
    let reopened =
        reopen_managed_connection_validated(&path, ConnectionMode::ValidatedReopen, |_| Ok(()));
    assert!(reopened.is_ok());

    let base_after = save_dacl(&base, &workspace_target.join("dacl-sentinel-after.txt"));
    assert_eq!(
        base_before, base_after,
        "the guard escaped the fixture: the sentinel base DACL changed"
    );

    // The writes provably landed inside the fixture: the saved SDDL of the
    // daemon directory must carry the guard's protected-DACL marker (D:P),
    // while the sentinel base keeps its auto-inherited marker (D:AI). The
    // snapshots are UTF-16; decode before matching markers.
    save_dacl(&daemon, &workspace_target.join("dacl-daemon.txt"));
    let decode = |file: &std::path::Path| {
        let bytes = std::fs::read(file).expect("snapshot file");
        String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
    };
    let daemon_sddl = decode(&workspace_target.join("dacl-daemon.txt"));
    let base_sddl = decode(&workspace_target.join("dacl-sentinel-after.txt"));
    assert!(
        daemon_sddl.contains("D:P"),
        "daemon directory was not DACL-restricted: {daemon_sddl}"
    );
    assert!(
        base_sddl.contains("D:AI"),
        "sentinel base lost its inherited DACL: {base_sddl}"
    );

    drop(reopened);
    drop(fixture);
    let _ = std::fs::remove_dir_all(&base);
    for name in [
        "dacl-canary-before.txt",
        "dacl-canary-after.txt",
        "dacl-sentinel-before.txt",
        "dacl-sentinel-after.txt",
        "dacl-daemon.txt",
    ] {
        let _ = std::fs::remove_file(workspace_target.join(name));
    }
}

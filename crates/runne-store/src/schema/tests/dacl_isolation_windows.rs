// Windows isolation regression: the identity guard's DACL writes must stay
// inside the test-owned fixture, never escape to a shared parent.
//
// Everything lives inside one unique disposable temp directory created in
// the workspace target directory — deliberately NOT the shared user TEMP:
//
//   <unique TempDir>              sentinel base (its DACL is the witness)
//   ├── canary/                   deliberately restricted to prove the
//   │                             comparator actually detects a change
//   ├── <fixture TempDir>/        the store fixture (tempdir_in the base)
//   │   └── runne-daemon/         daemon directory the guard restricts
//   │       └── event-log.sqlite
//   └── dacl-*.txt                icacls /save snapshots (UTF-16)
//
// Proof obligations: (1) the sentinel base DACL is byte-identical before
// and after a real Writer + ValidatedReopen scenario; (2) the comparator
// detects changes — the canary restricted through the same
// `secure_dir_permissions` the guard uses must produce a different
// snapshot; (3) the daemon directory carries the guard's protected-DACL
// marker (D:P). Nothing about the base's starting state is assumed: no
// inherited-DACL marker is required to be present. The unique TempDir
// removes the directory on drop, snapshots included — no fixed shared
// path is created or cleaned.

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
    // Unique per invocation: two concurrent instances never share a base.
    let base = tempfile::Builder::new()
        .prefix("dacl-sentinel")
        .tempdir_in(&workspace_target)
        .expect("sentinel base inside the workspace target directory");
    let base_path: PathBuf = base.path().to_path_buf();

    // Detector sensitivity: restricting our own canary must be visible.
    let canary = base_path.join("canary");
    std::fs::create_dir(&canary).unwrap();
    let canary_before = save_dacl(&canary, &base_path.join("dacl-canary-before.txt"));
    secure_dir_permissions(&canary).expect("canary restriction");
    let canary_after = save_dacl(&canary, &base_path.join("dacl-canary-after.txt"));
    assert_ne!(
        canary_before, canary_after,
        "detector insensitive: restricting a directory did not change its saved DACL"
    );

    // The real scenario, inside a fixture tempdir under the sentinel base:
    // runtime root = fixture tempdir, daemon directory = one level deeper.
    let fixture = tempfile::tempdir_in(&base_path).expect("fixture tempdir inside sentinel base");
    let daemon = fixture.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    let path = daemon.join("event-log.sqlite");
    let base_before = save_dacl(base.path(), &base_path.join("dacl-sentinel-before.txt"));

    let writer = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    writer
        .execute_batch("INSERT INTO _daemon_info (key, value) VALUES ('probe-isolation', 'one');")
        .unwrap();
    drop(writer);
    let reopened =
        reopen_managed_connection_validated(&path, ConnectionMode::ValidatedReopen, |_| Ok(()));
    assert!(reopened.is_ok());

    let base_after = save_dacl(base.path(), &base_path.join("dacl-sentinel-after.txt"));
    assert_eq!(
        base_before, base_after,
        "the guard escaped the fixture: the sentinel base DACL changed"
    );

    // The writes provably landed inside the fixture: the daemon directory's
    // saved SDDL must carry the guard's protected-DACL marker (D:P). The
    // snapshots are UTF-16; decode before matching markers. The base's
    // starting state is deliberately not assumed — its unchanged bytes are
    // the isolation proof.
    save_dacl(&daemon, &base_path.join("dacl-daemon.txt"));
    let decode = |file: &std::path::Path| {
        let bytes = std::fs::read(file).expect("snapshot file");
        String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
    };
    let daemon_sddl = decode(&base_path.join("dacl-daemon.txt"));
    assert!(
        daemon_sddl.contains("D:P"),
        "daemon directory was not DACL-restricted: {daemon_sddl}"
    );

    drop(reopened);
    drop(fixture);
    // Dropping `base` removes the sentinel, the canary, the fixture
    // remnants and every snapshot file — nothing fixed or shared remains.
    drop(base);
}

use recovery_fixtures::sha256_file;

fn fixture_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recovery")
}

fn source_checksums() -> Vec<(std::path::PathBuf, String)> {
    recovery_fixtures::load_manifest()
        .unwrap()
        .fixtures
        .iter()
        .map(|entry| (fixture_root().join(&entry.path), entry.sha256.clone()))
        .collect()
}

fn assert_source_checksums(checksums: &[(std::path::PathBuf, String)]) {
    for (path, checksum) in checksums {
        assert_eq!(sha256_file(path).unwrap(), *checksum);
    }
}

#[test]
fn loader_rejects_relative_destination_without_creating_a_file() {
    let destination = std::path::PathBuf::from("task5-relative/blocked.sqlite");
    let error = load_manifest_and_copy_fixture("event-integrity-v1.sqlite", &destination)
        .expect_err("relative destinations must be rejected");
    assert_eq!(error, "fixture destination must be absolute");
    assert!(!destination.exists());
}

#[test]
fn loader_rejects_an_existing_destination_without_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("existing.sqlite");
    std::fs::write(&destination, b"sentinel").unwrap();
    let checksums = source_checksums();

    let error = load_manifest_and_copy_fixture("event-integrity-v1.sqlite", &destination)
        .expect_err("existing destinations must be rejected");

    assert_eq!(error, "fixture destination already exists");
    assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
    assert_source_checksums(&checksums);
}

#[cfg(unix)]
#[test]
fn loader_rejects_an_existing_symlink_destination_without_following_it() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.sqlite");
    let destination = directory.path().join("destination.sqlite");
    std::fs::write(&target, b"sentinel").unwrap();
    std::os::unix::fs::symlink(&target, &destination).unwrap();

    let error = load_manifest_and_copy_fixture("event-integrity-v1.sqlite", &destination)
        .expect_err("existing symlink destinations must be rejected");

    assert_eq!(error, "fixture destination already exists");
    assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
}

#[cfg(unix)]
#[test]
fn loader_rejects_a_parent_symlink_into_the_fixture_tree() {
    let directory = tempfile::tempdir().unwrap();
    let parent_link = directory.path().join("fixture-link");
    std::os::unix::fs::symlink(fixture_root(), &parent_link).unwrap();
    let destination = parent_link.join("blocked/copy.sqlite");

    let error = load_manifest_and_copy_fixture("event-integrity-v1.sqlite", &destination)
        .expect_err("fixture-tree parent symlinks must be rejected");

    assert_eq!(
        error,
        "fixture destination parent must be outside the repository fixture directory"
    );
    assert!(!destination.exists());
}

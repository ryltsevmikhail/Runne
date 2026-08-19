use std::path::{Path, PathBuf};

use fixture_readers::{schema_versions, sidecars, validate_events};
use recovery_fixtures::{load_manifest, load_manifest_and_copy_fixture, FixtureKind, RecoveryFixtureEntry};

fn copied_fixture(name: &str) -> (tempfile::TempDir, PathBuf, RecoveryFixtureEntry) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(name);
    let entry = load_manifest_and_copy_fixture(name, &path).unwrap();
    (directory, path, entry)
}

fn expected_rows(entry: &RecoveryFixtureEntry) -> Vec<std::collections::BTreeMap<String, String>> {
    entry
        .expected_rows
        .iter()
        .map(|row| {
            assert_eq!(row.table, "events");
            assert_eq!(row.columns.get("event_id"), Some(&row.primary_key_hex));
            row.columns.clone()
        })
        .collect()
}

fn assert_read_without_rewrite(name: &str, profile: u16) {
    let (_directory, path, entry) = copied_fixture(name);
    let before = validate_events(&path, profile).unwrap();
    assert_eq!(before, expected_rows(&entry));
    let versions = schema_versions(&path).unwrap();
    assert_eq!(sidecars(&path), (false, false));

    let after = validate_events(&path, profile).unwrap();
    assert_eq!(after, before);
    assert_eq!(schema_versions(&path).unwrap(), versions);
    assert_eq!(sidecars(&path), (false, false));
    assert!(after.iter().all(|row| row["integrity_profile"] == profile.to_string()));
}

#[test]
fn manifest_accepts_only_checksum_verified_fixture_entries() {
    let manifest = load_manifest().unwrap();
    assert_eq!(manifest.manifest_version, 1);
    assert_eq!(manifest.fixtures.len(), 3);
    assert_eq!(
        manifest
            .fixtures
            .iter()
            .filter(|entry| entry.fixture_kind == FixtureKind::HistoricalExtracted)
            .count(),
        2
    );
    assert_eq!(
        manifest
            .fixtures
            .iter()
            .filter(|entry| entry.fixture_kind == FixtureKind::SyntheticTestVector)
            .count(),
        1
    );
}

#[test]
fn loader_refuses_a_destination_inside_the_repository_fixture_directory() {
    let destination = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recovery/blocked/copy.sqlite");
    let error = load_manifest_and_copy_fixture("event-integrity-v1.sqlite", &destination)
        .expect_err("repository fixture destinations must be rejected");
    assert_eq!(error, "fixture destination must be outside the repository fixture directory");
    assert!(!destination.exists());
}

#[test]
fn v1_taskrun_fixture_uses_the_current_v1_decoder_and_integrity_profile() {
    assert_read_without_rewrite("event-integrity-v1.sqlite", 1);
}

#[test]
fn v2_conversation_fixture_uses_the_current_v2_decoder_and_integrity_profile() {
    assert_read_without_rewrite("event-integrity-v2.sqlite", 2);
}

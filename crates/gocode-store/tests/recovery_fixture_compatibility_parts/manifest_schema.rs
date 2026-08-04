use recovery_fixtures::RecoveryFixtureManifest;

fn manifest_text() -> String {
    std::fs::read_to_string(fixture_root().join("manifest.json")).unwrap()
}

fn assert_unknown_field_rejected(manifest: String) {
    assert!(serde_json::from_str::<RecoveryFixtureManifest>(&manifest).is_err());
}

#[test]
fn manifest_rejects_an_unknown_top_level_field() {
    assert_unknown_field_rejected(manifest_text().replacen('{', "{\"unexpected\":true,", 1));
}

#[test]
fn manifest_rejects_an_unknown_fixture_entry_field() {
    assert_unknown_field_rejected(manifest_text().replacen(
        "\"path\": \"event-integrity-v1.sqlite\"",
        "\"unexpected\":true,\"path\": \"event-integrity-v1.sqlite\"",
        1,
    ));
}

#[test]
fn manifest_rejects_an_unknown_expected_row_field() {
    assert_unknown_field_rejected(manifest_text().replacen(
        "\"table\":\"events\"",
        "\"unexpected\":true,\"table\":\"events\"",
        1,
    ));
}

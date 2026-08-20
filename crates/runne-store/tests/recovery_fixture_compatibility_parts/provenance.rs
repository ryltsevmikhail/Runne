#[test]
fn manifest_writer_provenance_resolves_at_each_source_commit() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = recovery_fixtures::load_manifest().unwrap();
    recovery_fixture_provenance::validate_manifest_provenance(&workspace, &manifest).unwrap();
}

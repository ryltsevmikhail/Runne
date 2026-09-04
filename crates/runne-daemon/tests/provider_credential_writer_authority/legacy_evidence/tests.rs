use super::*;

fn bindings(temporary: &tempfile::TempDir, candidate: &str) -> LegacyEvidenceBindings {
    LegacyEvidenceBindings::from_values(
        candidate.repeat(64),
        "b".repeat(64),
        "run-1".to_owned(),
        temporary.path().join(format!("{candidate}-final.json")),
    )
    .expect("bindings")
}

fn complete() -> LegacyCleanupEvidence {
    let mut evidence = LegacyCleanupEvidence::default();
    for selector in SELECTORS {
        evidence.record(selector, "observation");
    }
    evidence
}

fn fragment(candidate: &str, selectors: &str) -> String {
    format!(
        "{{\"candidate_sha256\":\"{}\",\"scenario\":\"legacy-import\",\"selectors\":{{{selectors}}},\"tuple_sha256\":\"{}\",\"workflow_run_id\":\"run-1\"}}",
        candidate.repeat(64),
        "b".repeat(64)
    )
}

#[test]
fn complete_scenario_writes_the_exact_structural_envelope() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let path = temporary.path().join("evidence.json");
    complete()
        .write_envelope(&path, &"a".repeat(64), &"b".repeat(64), "run-1")
        .expect("envelope");
    let written = std::fs::read_to_string(path).expect("envelope read");
    assert!(written.contains("\"schema_version\":\"legacy-source-cleanup-evidence.v1\""));
    assert_eq!(written.matches("\"status\"").count(), 7);
}

#[test]
fn incomplete_duplicate_and_foreign_selectors_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let mut evidence = LegacyCleanupEvidence::default();
    evidence.record(AUTHORIZED_IMPORT, "one");
    assert_eq!(
        evidence.write_envelope(
            &temporary.path().join("evidence.json"),
            &"a".repeat(64),
            &"b".repeat(64),
            "run-1"
        ),
        Err("legacy evidence scenario is incomplete")
    );
    assert!(
        std::panic::catch_unwind(|| {
            let mut duplicate = LegacyCleanupEvidence::default();
            duplicate.record(AUTHORIZED_IMPORT, "one");
            duplicate.record(AUTHORIZED_IMPORT, "two");
        })
        .is_err()
    );
}

#[test]
fn invalid_expected_identities_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    assert_eq!(
        complete().write_envelope(
            &temporary.path().join("one"),
            &"A".repeat(64),
            &"b".repeat(64),
            "run-1"
        ),
        Err("legacy evidence expected digest is invalid")
    );
    assert_eq!(
        complete().write_envelope(
            &temporary.path().join("two"),
            &"a".repeat(64),
            &"b".repeat(64),
            "bad id;rm"
        ),
        Err("legacy evidence workflow identity is invalid")
    );
}

#[test]
fn observation_digests_are_deterministic_and_discriminating() {
    let mut first = LegacyCleanupEvidence::default();
    let mut second = LegacyCleanupEvidence::default();
    first.record(AUTHORIZED_IMPORT, "fact");
    first.record(DURABLE_CUTOVER, "fact");
    second.record(AUTHORIZED_IMPORT, "fact");
    second.record(DURABLE_CUTOVER, "other");
    assert_eq!(
        first.observations[AUTHORIZED_IMPORT],
        second.observations[AUTHORIZED_IMPORT]
    );
    assert_ne!(
        first.observations[DURABLE_CUTOVER],
        second.observations[DURABLE_CUTOVER]
    );
}

#[test]
fn envelope_writer_refuses_to_overwrite_an_existing_result() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let path = temporary.path().join("evidence.json");
    std::fs::write(&path, "untrusted-existing-result").expect("existing result");
    assert_eq!(
        complete().write_envelope(&path, &"a".repeat(64), &"b".repeat(64), "run-1"),
        Err("legacy evidence output already exists")
    );
    assert_eq!(
        std::fs::read_to_string(path).expect("existing result read"),
        "untrusted-existing-result"
    );
}

#[test]
fn fragment_reader_rejects_a_missing_child_result() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let bindings = bindings(&temporary, "a");
    assert!(matches!(
        LegacyCleanupEvidence::read_fragment(
            &temporary.path().join("missing.json"),
            "legacy-import",
            &bindings
        ),
        Err("legacy evidence fragment is missing")
    ));
}

#[test]
fn fragment_reader_rejects_a_foreign_identity_and_wrong_selector_set() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let expected_bindings = bindings(&temporary, "a");
    let path = temporary.path().join("fragment.json");
    let mut evidence = LegacyCleanupEvidence::default();
    evidence.record(AUTHORIZED_IMPORT, "import");
    evidence.record(DURABLE_CUTOVER, "cutover");
    evidence
        .write_fragment(&path, "legacy-import", &expected_bindings)
        .expect("fragment");
    assert!(matches!(
        LegacyCleanupEvidence::read_fragment(&path, "legacy-import", &bindings(&temporary, "c")),
        Err("legacy evidence fragment identity is invalid")
    ));
    let incomplete = temporary.path().join("incomplete.json");
    std::fs::write(&incomplete, fragment("a", "\"authorized_import\":{\"observation_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"status\":\"verified\"}")).expect("fragment");
    assert!(matches!(
        LegacyCleanupEvidence::read_fragment(&incomplete, "legacy-import", &expected_bindings),
        Err("legacy evidence fragment selectors are invalid")
    ));
}

#[test]
fn fragment_reader_rejects_duplicate_and_unknown_selectors() {
    let temporary = tempfile::tempdir().expect("temporary evidence root");
    let bindings = bindings(&temporary, "a");
    for (name, selectors) in [
        (
            "duplicate.json",
            "\"authorized_import\":{\"observation_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"status\":\"verified\"},\"authorized_import\":{\"observation_sha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"status\":\"verified\"}",
        ),
        (
            "unknown.json",
            "\"authorized_import\":{\"observation_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"status\":\"verified\"},\"unknown\":{\"observation_sha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"status\":\"verified\"}",
        ),
    ] {
        let path = temporary.path().join(name);
        std::fs::write(&path, fragment("a", selectors)).expect("fragment");
        assert!(matches!(
            LegacyCleanupEvidence::read_fragment(&path, "legacy-import", &bindings),
            Err("legacy evidence fragment selectors are invalid")
        ));
    }
}

//! Dedicated legacy import/cutover/delete/crash native scenario.
//!
//! The scenario runs only under the disposable Keychain rig on an isolated
//! darwin arm64 host through the pinned `--ignored` invocation. Until its
//! native stages are implemented it fails closed: it validates the runner
//! binding and then refuses, so a green result can never be produced without
//! the real chain.

use super::legacy_evidence::{
    LEGACY_CLEANUP_CANDIDATE_ENV, LEGACY_CLEANUP_EVIDENCE_ENV, LEGACY_CLEANUP_RUN_ID_ENV,
    LEGACY_CLEANUP_TUPLE_ENV, is_evidence_digest_shape, is_evidence_run_id_shape,
};

#[test]
#[ignore = "real native scenario; isolated disposable macOS host only"]
fn legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone() {
    let environment = scenario_binding_from_environment();
    // Native stages (legacy seeding, authorized import, durable cutover,
    // exact deletion, delete-before-confirmation crash, restart absence
    // readback, tombstone, replacement/ambiguity denial, evidence emission)
    // are the next implementation slice. Refuse rather than pass.
    let ScenarioBinding {
        candidate_sha256,
        tuple_sha256,
        workflow_run_id,
        evidence,
    } = environment;
    assert!(!candidate_sha256.is_empty());
    assert!(!tuple_sha256.is_empty());
    assert!(!workflow_run_id.is_empty());
    assert!(!evidence.as_os_str().is_empty());
    panic!("native legacy cleanup scenario stages are not implemented yet");
}

fn scenario_binding_from_environment() -> ScenarioBinding {
    let evidence = std::env::var_os(LEGACY_CLEANUP_EVIDENCE_ENV)
        .ok_or("scenario binding is missing the evidence path")
        .expect("scenario evidence path binding");
    let read = |name: &'static str| -> String {
        match std::env::var(name) {
            Ok(value) => value,
            Err(_) => panic!("scenario binding is missing {name}"),
        }
    };
    let candidate_sha256 = read(LEGACY_CLEANUP_CANDIDATE_ENV);
    let tuple_sha256 = read(LEGACY_CLEANUP_TUPLE_ENV);
    let workflow_run_id = read(LEGACY_CLEANUP_RUN_ID_ENV);
    assert!(
        is_evidence_digest_shape(&candidate_sha256) && is_evidence_digest_shape(&tuple_sha256),
        "scenario candidate or tuple binding is invalid"
    );
    assert!(
        is_evidence_run_id_shape(&workflow_run_id),
        "scenario workflow identity is invalid"
    );
    ScenarioBinding {
        candidate_sha256,
        tuple_sha256,
        workflow_run_id,
        evidence: std::path::PathBuf::from(evidence),
    }
}

struct ScenarioBinding {
    candidate_sha256: String,
    tuple_sha256: String,
    workflow_run_id: String,
    evidence: std::path::PathBuf,
}

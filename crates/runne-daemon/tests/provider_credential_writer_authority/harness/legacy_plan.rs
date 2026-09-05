//! Legacy scenario child-plan and isolated-host preflight helpers.

use std::ffi::OsString;

use crate::legacy_evidence::{
    LEGACY_CLEANUP_CANDIDATE_ENV, LEGACY_CLEANUP_EVIDENCE_ENV, LEGACY_CLEANUP_RUN_ID_ENV,
    LEGACY_CLEANUP_TUPLE_ENV, LegacyEvidenceBindings,
};

const ISOLATED_ENV: &str = "RUNNE_LEGACY_CLEANUP_ISOLATED";

pub struct LegacyChildPlan {
    pub args: Vec<&'static str>,
    pub environment: Vec<(&'static str, OsString)>,
}

pub fn legacy_preflight(
    isolated: &str,
    candidate: String,
    tuple: String,
    run_id: String,
    final_path: std::path::PathBuf,
) -> Result<LegacyEvidenceBindings, &'static str> {
    if isolated != "1" {
        return Err("legacy cleanup isolated host opt-in is required");
    }
    LegacyEvidenceBindings::from_values(candidate, tuple, run_id, final_path)
}

pub(super) fn legacy_preflight_from_environment(
    bindings: LegacyEvidenceBindings,
) -> Result<LegacyEvidenceBindings, &'static str> {
    if std::env::var(ISOLATED_ENV).as_deref() != Ok("1") {
        return Err("legacy cleanup isolated host opt-in is missing");
    }
    Ok(bindings)
}

pub fn legacy_child_plan(
    selector: &'static str,
    _scenario: &'static str,
    child_path: std::path::PathBuf,
    bindings: &LegacyEvidenceBindings,
) -> LegacyChildPlan {
    LegacyChildPlan {
        args: vec![
            "--ignored",
            "--exact",
            selector,
            "--nocapture",
            "--test-threads=1",
        ],
        environment: vec![
            (
                LEGACY_CLEANUP_CANDIDATE_ENV,
                OsString::from(bindings.candidate_sha256()),
            ),
            (LEGACY_CLEANUP_EVIDENCE_ENV, child_path.into_os_string()),
            (
                LEGACY_CLEANUP_RUN_ID_ENV,
                OsString::from(bindings.workflow_run_id()),
            ),
            (
                LEGACY_CLEANUP_TUPLE_ENV,
                OsString::from(bindings.tuple_sha256()),
            ),
        ],
    }
}

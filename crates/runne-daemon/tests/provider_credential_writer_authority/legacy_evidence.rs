//! Builds the exact `legacy-source-cleanup-evidence.v1` envelope from real
//! scenario outcomes. The envelope never carries secrets, native paths or
//! receipts: each selector collapses to one SHA-256 observation digest.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

#[path = "legacy_evidence/fragment.rs"]
mod fragment;
#[cfg(test)]
#[path = "legacy_evidence/tests.rs"]
mod tests;

pub(super) use fragment::LegacyEvidenceBindings;

pub(super) const SCHEMA_VERSION: &str = "legacy-source-cleanup-evidence.v1";
pub(super) const AUTHORIZED_IMPORT: &str = "authorized_import";
pub(super) const DURABLE_CUTOVER: &str = "durable_cutover";
pub(super) const REPLACEMENT_DENIED: &str = "replacement_denied";
pub(super) const AMBIGUOUS_SOURCE_DENIED: &str = "ambiguous_source_denied";
pub(super) const EXACT_SOURCE_DELETED: &str = "exact_source_deleted";
pub(super) const RESTART_AFTER_DELETE: &str = "restart_after_delete_before_confirmation";
pub(super) const REIMPORT_DENIED: &str = "reimport_denied";

const SELECTORS: [&str; 7] = [
    AUTHORIZED_IMPORT,
    DURABLE_CUTOVER,
    REPLACEMENT_DENIED,
    AMBIGUOUS_SOURCE_DENIED,
    EXACT_SOURCE_DELETED,
    RESTART_AFTER_DELETE,
    REIMPORT_DENIED,
];
const LEGACY_SCENARIOS: [(&str, &[&str]); 4] = [
    ("legacy-import", &[AUTHORIZED_IMPORT, DURABLE_CUTOVER]),
    (
        "legacy-crash-delete",
        &[EXACT_SOURCE_DELETED, RESTART_AFTER_DELETE, REIMPORT_DENIED],
    ),
    ("legacy-replacement-denied", &[REPLACEMENT_DENIED]),
    ("legacy-ambiguous-denied", &[AMBIGUOUS_SOURCE_DENIED]),
];
pub(super) const LEGACY_SCENARIO_NAMES: [&str; 4] = [
    "legacy-import",
    "legacy-crash-delete",
    "legacy-replacement-denied",
    "legacy-ambiguous-denied",
];
pub(super) const LEGACY_CLEANUP_CANDIDATE_ENV: &str = "RUNNE_LEGACY_CLEANUP_CANDIDATE";
pub(super) const LEGACY_CLEANUP_TUPLE_ENV: &str = "RUNNE_LEGACY_CLEANUP_TUPLE";
pub(super) const LEGACY_CLEANUP_RUN_ID_ENV: &str = "RUNNE_LEGACY_CLEANUP_RUN_ID";
pub(super) const LEGACY_CLEANUP_EVIDENCE_ENV: &str = "RUNNE_LEGACY_CLEANUP_EVIDENCE";

#[derive(Default)]
pub(super) struct LegacyCleanupEvidence {
    observations: BTreeMap<&'static str, String>,
}

impl LegacyCleanupEvidence {
    pub(super) fn record(&mut self, selector: &'static str, observation: &str) {
        assert!(
            SELECTORS.contains(&selector),
            "unknown legacy cleanup selector"
        );
        assert!(
            !observation.is_empty(),
            "legacy cleanup observation must be non-empty"
        );
        assert!(
            self.observations
                .insert(
                    selector,
                    hex::encode(Sha256::digest(observation.as_bytes()))
                )
                .is_none(),
            "duplicate legacy cleanup selector"
        );
    }

    pub(super) fn write_envelope(
        self,
        path: &Path,
        candidate_sha256: &str,
        tuple_sha256: &str,
        workflow_run_id: &str,
    ) -> Result<(), &'static str> {
        if self.observations.len() != SELECTORS.len() {
            return Err("legacy evidence scenario is incomplete");
        }
        if ![candidate_sha256, tuple_sha256]
            .into_iter()
            .all(is_evidence_digest)
        {
            return Err("legacy evidence expected digest is invalid");
        }
        if !is_evidence_run_id_shape(workflow_run_id) {
            return Err("legacy evidence workflow identity is invalid");
        }
        let selectors = SELECTORS.map(|selector| {
            format!(
                "\"{selector}\":{{\"observation_sha256\":\"{}\",\"status\":\"verified\"}}",
                self.observations[selector]
            )
        });
        write_new(path, format!("{{\"candidate_sha256\":\"{candidate_sha256}\",\"schema_version\":\"{SCHEMA_VERSION}\",\"selectors\":{{{}}},\"tuple_sha256\":\"{tuple_sha256}\",\"workflow_run_id\":\"{workflow_run_id}\"}}", selectors.join(",")).as_bytes())
    }

    pub(super) fn write_fragment(
        &self,
        path: &Path,
        scenario: &str,
        bindings: &LegacyEvidenceBindings,
    ) -> Result<(), &'static str> {
        fragment::write_fragment(self, path, scenario, bindings)
    }

    pub(super) fn read_fragment(
        path: &Path,
        scenario: &str,
        bindings: &LegacyEvidenceBindings,
    ) -> Result<Self, &'static str> {
        fragment::read_fragment(path, scenario, bindings)
    }

    pub(super) fn merge(&mut self, child: Self) -> Result<(), &'static str> {
        for (selector, digest) in child.observations {
            if self.observations.insert(selector, digest).is_some() {
                return Err("legacy evidence fragment selectors are invalid");
            }
        }
        Ok(())
    }
}

pub(super) fn scenario_selectors(scenario: &str) -> Result<&'static [&'static str], &'static str> {
    LEGACY_SCENARIOS
        .iter()
        .find_map(|(name, selectors)| (*name == scenario).then_some(*selectors))
        .ok_or("unknown legacy cleanup scenario")
}

pub(super) fn is_complete_selector_set(
    evidence: &LegacyCleanupEvidence,
    expected: &[&str],
) -> bool {
    evidence.observations.len() == expected.len()
        && expected
            .iter()
            .all(|selector| evidence.observations.contains_key(selector))
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err("legacy evidence output already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("legacy evidence output check failed"),
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => "legacy evidence output already exists",
            _ => "legacy evidence write failed",
        })?;
    output
        .write_all(bytes)
        .map_err(|_| "legacy evidence write failed")
}

pub(super) fn is_evidence_digest(value: &str) -> bool {
    is_evidence_digest_shape(value) && value != "0".repeat(64)
}

pub(super) fn is_evidence_digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn is_evidence_run_id_shape(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

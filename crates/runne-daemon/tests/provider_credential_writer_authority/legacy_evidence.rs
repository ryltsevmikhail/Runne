//! Builds the exact `legacy-source-cleanup-evidence.v1` envelope from real
//! scenario outcomes. The envelope never carries secrets, native paths or
//! receipts: each selector collapses to one SHA-256 observation digest.
//! Writing an envelope is not qualification — protected enforcement and
//! signature verification remain separate mandatory gates.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest as _, Sha256};

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

pub(super) const LEGACY_CLEANUP_CANDIDATE_ENV: &str = "RUNNE_LEGACY_CLEANUP_CANDIDATE";
pub(super) const LEGACY_CLEANUP_TUPLE_ENV: &str = "RUNNE_LEGACY_CLEANUP_TUPLE";
pub(super) const LEGACY_CLEANUP_RUN_ID_ENV: &str = "RUNNE_LEGACY_CLEANUP_RUN_ID";
pub(super) const LEGACY_CLEANUP_EVIDENCE_ENV: &str = "RUNNE_LEGACY_CLEANUP_EVIDENCE";

/// Collects one digest per scenario selector and fails closed on duplicates.
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
        let digest = hex::encode(Sha256::digest(observation.as_bytes()));
        let previous = self.observations.insert(selector, digest);
        assert!(previous.is_none(), "duplicate legacy cleanup selector");
    }

    /// Writes the exact envelope accepted by the structural contract.
    ///
    /// # Errors
    ///
    /// Returns a static failure for incomplete scenarios, invalid expected
    /// identities, or an unwritable evidence path.
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
        for digest in [candidate_sha256, tuple_sha256] {
            if !is_evidence_digest(digest) {
                return Err("legacy evidence expected digest is invalid");
            }
        }
        if !is_evidence_run_id_shape(workflow_run_id) {
            return Err("legacy evidence workflow identity is invalid");
        }
        let selectors = SELECTORS
            .map(|selector| {
                let digest = &self.observations[selector];
                format!(
                    "\"{selector}\":{{\"observation_sha256\":\"{digest}\",\"status\":\"verified\"}}"
                )
            })
            .join(",");
        let envelope = format!(
            "{{\"candidate_sha256\":\"{candidate_sha256}\",\
             \"schema_version\":\"{SCHEMA_VERSION}\",\
             \"selectors\":{{{selectors}}},\
             \"tuple_sha256\":\"{tuple_sha256}\",\
             \"workflow_run_id\":\"{}\"}}",
            workflow_run_id
        );
        std::fs::write(path, envelope).map_err(|_| "legacy evidence write failed")
    }
}

fn is_evidence_digest(value: &str) -> bool {
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

#[test]
fn complete_scenario_writes_the_exact_structural_envelope() {
    let mut evidence = LegacyCleanupEvidence::default();
    for selector in SELECTORS {
        evidence.record(selector, "canonical-observation");
    }
    let path = std::env::temp_dir().join("runne-legacy-evidence-complete.json");
    evidence
        .write_envelope(&path, &"a".repeat(64), &"b".repeat(64), "run-1")
        .expect("envelope");
    let written = std::fs::read_to_string(&path).expect("envelope read");
    std::fs::remove_file(&path).expect("cleanup");
    assert!(written.contains("\"schema_version\":\"legacy-source-cleanup-evidence.v1\""));
    for selector in SELECTORS {
        assert!(written.contains(&format!("\"{selector}\":{{")));
        assert!(written.contains(&format!("\"{selector}\":{{\"observation_sha256\":")));
    }
    assert!(written.contains("\"status\":\"verified\""));
    assert_eq!(written.matches("\"status\"").count(), 7);
}

#[test]
fn incomplete_duplicate_and_foreign_selectors_fail_closed() {
    let mut evidence = LegacyCleanupEvidence::default();
    evidence.record(AUTHORIZED_IMPORT, "one");
    let path = std::env::temp_dir().join("runne-legacy-evidence-incomplete.json");
    assert_eq!(
        evidence.write_envelope(&path, &"a".repeat(64), &"b".repeat(64), "run-1"),
        Err("legacy evidence scenario is incomplete")
    );
    let mut duplicate = LegacyCleanupEvidence::default();
    duplicate.record(AUTHORIZED_IMPORT, "one");
    let duplicate_result =
        std::panic::catch_unwind(move || duplicate.record(AUTHORIZED_IMPORT, "two"));
    assert!(duplicate_result.is_err());
}

#[test]
fn invalid_expected_identities_fail_closed() {
    let complete = || {
        let mut evidence = LegacyCleanupEvidence::default();
        for selector in SELECTORS {
            evidence.record(selector, "canonical-observation");
        }
        evidence
    };
    let path = std::env::temp_dir().join("runne-legacy-evidence-identity.json");
    assert_eq!(
        complete().write_envelope(&path, &"A".repeat(64), &"b".repeat(64), "run-1"),
        Err("legacy evidence expected digest is invalid")
    );
    assert_eq!(
        complete().write_envelope(&path, &"0".repeat(64), &"b".repeat(64), "run-1"),
        Err("legacy evidence expected digest is invalid")
    );
    assert_eq!(
        complete().write_envelope(&path, &"a".repeat(64), &"b".repeat(64), ""),
        Err("legacy evidence workflow identity is invalid")
    );
    assert_eq!(
        complete().write_envelope(&path, &"a".repeat(64), &"b".repeat(64), "bad id;rm"),
        Err("legacy evidence workflow identity is invalid")
    );
}

#[test]
fn observation_digests_are_deterministic_and_discriminating() {
    let mut first = LegacyCleanupEvidence::default();
    let mut second = LegacyCleanupEvidence::default();
    first.record(AUTHORIZED_IMPORT, "authorized-import-fact");
    first.record(DURABLE_CUTOVER, "authorized-import-fact");
    second.record(AUTHORIZED_IMPORT, "authorized-import-fact");
    second.record(DURABLE_CUTOVER, "other-fact");
    let same = first.observations[AUTHORIZED_IMPORT] == second.observations[AUTHORIZED_IMPORT];
    let different = first.observations[DURABLE_CUTOVER] != second.observations[DURABLE_CUTOVER];
    assert!(same && different);
    assert_ne!(first.observations[AUTHORIZED_IMPORT], "0".repeat(64));
}

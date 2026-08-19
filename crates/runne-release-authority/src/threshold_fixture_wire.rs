//! Strict canonical wire projection for durable fixture threshold state.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::threshold_fixture::ThresholdFixtureStoreBinding;
use crate::{AuthorityError, Digest, ThresholdAdmissionScope, ThresholdVerificationState};

#[derive(Clone, Eq, PartialEq)]
pub struct FileState {
    pub(crate) state: ThresholdVerificationState,
    pub(crate) now: u64,
    pub(crate) journal: Vec<JournalEntry>,
    pub(crate) acknowledgements: Vec<Acknowledgement>,
}
#[derive(Clone, Eq, PartialEq)]
pub struct JournalEntry {
    pub(crate) scope: ThresholdAdmissionScope,
    pub(crate) admission: Digest,
    pub(crate) next: ThresholdVerificationState,
}
#[derive(Clone, Eq, PartialEq)]
pub struct Acknowledgement {
    pub(crate) admission: Digest,
    pub(crate) revision: u64,
}

pub fn encode(file: &FileState, binding: &ThresholdFixtureStoreBinding) -> Vec<u8> {
    let mut text = String::from("runne.release.durable-threshold-context/1\n");
    line(&mut text, "bootstrap", &binding.bootstrap.to_hex());
    line(&mut text, "profile", &binding.profile);
    line(&mut text, "version", &binding.version.to_string());
    line(&mut text, "now", &file.now.to_string());
    state(&mut text, "state", &file.state);
    line(&mut text, "journal_count", &file.journal.len().to_string());
    for entry in &file.journal {
        journal(&mut text, entry);
    }
    line(
        &mut text,
        "ack_count",
        &file.acknowledgements.len().to_string(),
    );
    for ack in &file.acknowledgements {
        line(
            &mut text,
            "ack",
            &format!("{}@{}", ack.admission.to_hex(), ack.revision),
        );
    }
    text.into_bytes()
}
fn state(out: &mut String, prefix: &str, value: &ThresholdVerificationState) {
    line(
        out,
        &format!("{prefix}_versions"),
        &numbers(&value.versions),
    );
    line(
        out,
        &format!("{prefix}_rollback_floor"),
        &value.rollback_floor.to_string(),
    );
    line(
        out,
        &format!("{prefix}_revocation_floor"),
        &value.revocation_floor.to_string(),
    );
    line(
        out,
        &format!("{prefix}_frozen"),
        if value.frozen { "1" } else { "0" },
    );
    line(
        out,
        &format!("{prefix}_generation"),
        &value.generation.to_string(),
    );
    line(out, &format!("{prefix}_root_keys"), &keys(&value.root_keys));
    line(
        out,
        &format!("{prefix}_targets_keys"),
        &keys(&value.targets_keys),
    );
    line(
        out,
        &format!("{prefix}_snapshot_key"),
        &format!("{}@{}", value.snapshot_key.0, hex(&value.snapshot_key.1)),
    );
    line(
        out,
        &format!("{prefix}_timestamp_key"),
        &format!("{}@{}", value.timestamp_key.0, hex(&value.timestamp_key.1)),
    );
    line(
        out,
        &format!("{prefix}_channel_policy_id"),
        value.channel_policy_id.as_deref().unwrap_or(""),
    );
    line(
        out,
        &format!("{prefix}_role_bodies"),
        &value
            .role_bodies
            .iter()
            .map(|(role, body)| format!("{role}@{}", hex(body)))
            .collect::<Vec<_>>()
            .join(","),
    );
    line(
        out,
        &format!("{prefix}_role_digests"),
        &value
            .role_digests
            .iter()
            .map(|(role, digest)| format!("{role}@{}", digest.to_hex()))
            .collect::<Vec<_>>()
            .join(","),
    );
}
fn journal(out: &mut String, entry: &JournalEntry) {
    let scope = &entry.scope;
    line(
        out,
        "journal_scope",
        &format!(
            "{}@{}@{}@{}@{}@{}@{}@{}@{}@{}",
            scope.authority_instance.to_hex(),
            hex(scope.promotion.as_bytes()),
            scope.revision,
            hex(scope.command.as_bytes()),
            scope.authorization.to_hex(),
            scope.commitment.to_hex(),
            scope.candidate.to_hex(),
            scope.inventory.to_hex(),
            scope.metadata.to_hex(),
            scope.report.to_hex()
        ),
    );
    line(out, "journal_admission", &entry.admission.to_hex());
    state(out, "journal_next", &entry.next);
}
fn line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}
fn numbers(values: &BTreeMap<String, u64>) -> String {
    values
        .iter()
        .map(|(k, v)| format!("{k}@{v}"))
        .collect::<Vec<_>>()
        .join(",")
}
fn keys(values: &BTreeMap<String, [u8; 32]>) -> String {
    values
        .iter()
        .map(|(k, v)| format!("{k}@{}", hex(v)))
        .collect::<Vec<_>>()
        .join(",")
}

#[path = "threshold_fixture_wire_read.rs"]
mod read;
pub use read::{canonical_id, decode, hex};

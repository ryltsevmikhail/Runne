//! Canonical fixture state snapshots produced only by successful store transitions.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::store::CommandFingerprint;
use crate::{AuthorityError, Digest, PromotionId, PromotionState};

#[cfg(any(test, feature = "fixture-only"))]
impl crate::InMemoryPromotionStore {
    /// Read the exact last successful canonical fixture snapshot.
    ///
    /// # Errors
    /// Returns an error when the promotion has no successful transition.
    pub fn snapshot(&self, id: &PromotionId) -> Result<PromotionStateSnapshot, AuthorityError> {
        self.entries
            .get(id)
            .and_then(|record| record.snapshot.clone())
            .ok_or(AuthorityError::InvalidTransition)
    }
}

/// Immutable fixture snapshot bytes and domain-separated digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionStateSnapshot {
    /// Canonical LF-terminated snapshot bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the canonical bytes.
    pub digest: Digest,
    /// Persisted store revision.
    pub revision: u64,
}

#[derive(Serialize)]
struct SnapshotWire<'a> {
    candidate_binding_sha256: String,
    candidate_sha256: String,
    command_fingerprint_sha256: String,
    domain: &'a str,
    effect_generation: u64,
    previous_snapshot_sha256: String,
    promotion_id: &'a str,
    revision: u64,
    schema_version: &'a str,
    state: &'a str,
}

pub fn build(
    id: &PromotionId,
    record: &crate::store_machine::Record,
    fingerprint: CommandFingerprint,
) -> Result<PromotionStateSnapshot, AuthorityError> {
    let binding = record.binding.ok_or(AuthorityError::BindingMismatch)?;
    let state = state(record.state.ok_or(AuthorityError::InvalidTransition)?);
    let previous = record
        .previous_snapshot
        .map_or_else(|| "0".repeat(64), Digest::to_hex);
    let wire = SnapshotWire {
        candidate_binding_sha256: binding.sha256().to_hex(),
        candidate_sha256: binding.candidate().to_hex(),
        command_fingerprint_sha256: fingerprint.digest().to_hex(),
        domain: "fixture",
        effect_generation: 0,
        previous_snapshot_sha256: previous,
        promotion_id: &id.0,
        revision: record.revision,
        schema_version: "gocode.release.promotion-state-snapshot/1",
        state,
    };
    let mut bytes = serde_json::to_vec(&wire).map_err(|_| AuthorityError::NonCanonicalPayload)?;
    bytes.push(b'\n');
    let digest = Digest::from_bytes(Sha256::digest(&bytes[..bytes.len() - 1]).into());
    Ok(PromotionStateSnapshot {
        bytes,
        digest,
        revision: record.revision,
    })
}

pub fn validate(
    id: &PromotionId,
    record: &crate::store_machine::Record,
) -> Result<(), AuthorityError> {
    let snapshot = record
        .snapshot
        .as_ref()
        .ok_or(AuthorityError::BindingMismatch)?;
    let parsed = crate::InspectedCanonicalPayload::parse(
        crate::CanonicalPayloadKind::Snapshot,
        &snapshot.bytes,
    )?;
    let fields = parsed
        .snapshot_parts()
        .ok_or(AuthorityError::NonCanonicalPayload)?;
    let binding = record.binding.ok_or(AuthorityError::BindingMismatch)?;
    let mut fingerprints = record
        .commands
        .values()
        .filter(|(_, outcome)| outcome.revision == record.revision)
        .map(|(fingerprint, _)| *fingerprint);
    let fingerprint = fingerprints.next().ok_or(AuthorityError::BindingMismatch)?;
    if fingerprints.next().is_some() {
        return Err(AuthorityError::BindingMismatch);
    }
    (snapshot.revision == record.revision
        && Digest::from_bytes(parsed.sha256()) == snapshot.digest
        && fields.promotion == id.0
        && fields.state == state(record.state.ok_or(AuthorityError::BindingMismatch)?)
        && fields.revision == record.revision
        && fields.candidate == binding.candidate()
        && fields.binding == binding.sha256()
        && fields.previous
            == record
                .previous_snapshot
                .unwrap_or(Digest::from_bytes([0; 32]))
        && fields.command == fingerprint.digest()
        && fields.effect_generation == 0
        && fields.domain == "fixture")
        .then_some(())
        .ok_or(AuthorityError::BindingMismatch)
}

const fn state(value: PromotionState) -> &'static str {
    match value {
        PromotionState::Rc0Ingested => "rc0_ingested",
        PromotionState::Rc1Review => "rc1_review",
        PromotionState::QualifiedUnsigned => "qualified_unsigned",
        PromotionState::SigningAuthorized => "signing_authorized",
        PromotionState::SignedEnvelopesVerified => "signed_envelopes_verified",
        PromotionState::Rc3Review => "rc3_review",
        PromotionState::PublicationAuthorized => "publication_authorized",
    }
}

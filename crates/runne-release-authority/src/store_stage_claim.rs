//! Persisted nonce tombstones for reservation-bound stage admissions.

use sha2::{Digest as _, Sha256};

#[derive(Clone, Eq, PartialEq)]
pub struct StoredStageClaim {
    pub(crate) nonce: String,
    pub(crate) envelope: [u8; 32],
    pub(crate) payload: [u8; 32],
    pub(crate) bootstrap: [u8; 32],
    pub(crate) role: String,
    pub(crate) promotion: String,
    pub(crate) revision: u64,
    pub(crate) command: String,
    pub(crate) kind: runne_promotion_contracts::CanonicalPayloadKind,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) admission_fingerprint: [u8; 32],
    pub(crate) bootstrap_not_before: String,
    pub(crate) bootstrap_expires_at: String,
    pub(crate) root_epoch: u64,
    pub(crate) envelope_not_before: String,
    pub(crate) envelope_expires_at: String,
    pub(crate) envelope_epoch: u64,
    pub(crate) payload_valid_from: u64,
    pub(crate) payload_expires_at: u64,
    pub(crate) payload_epoch: u64,
    pub(crate) role_floor: u64,
}
impl StoredStageClaim {
    pub(crate) fn from_request(
        request: &runne_project_owner_authority::StageAdmissionRequest<'_>,
        role_floor: u64,
    ) -> Self {
        Self {
            nonce: request.scope.authorization_nonce.into(),
            envelope: request.scope.envelope_sha256,
            payload: request.scope.payload_sha256,
            bootstrap: request.scope.bootstrap_receipt_sha256,
            role: request.scope.role.into(),
            promotion: request.scope.reservation.promotion().into(),
            revision: request.scope.reservation.revision(),
            command: request.scope.reservation.command().into(),
            kind: request.scope.reservation.kind(),
            fingerprint: request.scope.reservation.fingerprint(),
            admission_fingerprint: admission_fingerprint(request, role_floor),
            bootstrap_not_before: request.bootstrap_validity.not_before().into(),
            bootstrap_expires_at: request.bootstrap_validity.expires_at().into(),
            root_epoch: request.bootstrap_admission_scope.root_revocation_epoch(),
            envelope_not_before: request.envelope_not_before.into(),
            envelope_expires_at: request.envelope_expires_at.into(),
            envelope_epoch: request.envelope_revocation_epoch,
            payload_valid_from: request.payload_valid_from,
            payload_expires_at: request.payload_expires_at,
            payload_epoch: request.payload_revocation_epoch,
            role_floor,
        }
    }
}

pub fn admission_fingerprint(
    request: &runne_project_owner_authority::StageAdmissionRequest<'_>,
    role_floor: u64,
) -> [u8; 32] {
    let scope = request.scope.reservation;
    let fields: [&[u8]; 21] = [
        b"runne.release.stage-admission-command/1\0",
        &request.scope.bootstrap_receipt_sha256,
        request.scope.role.as_bytes(),
        &request.scope.payload_sha256,
        request.scope.authorization_nonce.as_bytes(),
        &request.scope.envelope_sha256,
        request.bootstrap_validity.not_before().as_bytes(),
        request.bootstrap_validity.expires_at().as_bytes(),
        &request
            .bootstrap_admission_scope
            .root_revocation_epoch()
            .to_be_bytes(),
        request.envelope_not_before.as_bytes(),
        request.envelope_expires_at.as_bytes(),
        &request.envelope_revocation_epoch.to_be_bytes(),
        &request.payload_valid_from.to_be_bytes(),
        &request.payload_expires_at.to_be_bytes(),
        &request.payload_revocation_epoch.to_be_bytes(),
        scope.promotion().as_bytes(),
        &scope.revision().to_be_bytes(),
        scope.command().as_bytes(),
        kind_name(scope.kind()).as_bytes(),
        &scope.fingerprint(),
        &role_floor.to_be_bytes(),
    ];
    framed_sha256(&fields)
}

pub fn stored_admission_fingerprint(claim: &StoredStageClaim) -> [u8; 32] {
    let fields: [&[u8]; 21] = [
        b"runne.release.stage-admission-command/1\0",
        &claim.bootstrap,
        claim.role.as_bytes(),
        &claim.payload,
        claim.nonce.as_bytes(),
        &claim.envelope,
        claim.bootstrap_not_before.as_bytes(),
        claim.bootstrap_expires_at.as_bytes(),
        &claim.root_epoch.to_be_bytes(),
        claim.envelope_not_before.as_bytes(),
        claim.envelope_expires_at.as_bytes(),
        &claim.envelope_epoch.to_be_bytes(),
        &claim.payload_valid_from.to_be_bytes(),
        &claim.payload_expires_at.to_be_bytes(),
        &claim.payload_epoch.to_be_bytes(),
        claim.promotion.as_bytes(),
        &claim.revision.to_be_bytes(),
        claim.command.as_bytes(),
        kind_name(claim.kind).as_bytes(),
        &claim.fingerprint,
        &claim.role_floor.to_be_bytes(),
    ];
    framed_sha256(&fields)
}

pub fn stored_command_fingerprint(claim: &StoredStageClaim) -> [u8; 32] {
    // The command transcript intentionally excludes the store-observed role floor.
    // Durable-wire validation binds that floor to the signed envelope epoch.
    let fields: [&[u8]; 17] = [
        b"runne.release.stage-admission-command/1\0",
        &claim.bootstrap,
        claim.role.as_bytes(),
        &claim.payload,
        claim.nonce.as_bytes(),
        &claim.envelope,
        claim.bootstrap_not_before.as_bytes(),
        claim.bootstrap_expires_at.as_bytes(),
        &claim.root_epoch.to_be_bytes(),
        claim.envelope_not_before.as_bytes(),
        claim.envelope_expires_at.as_bytes(),
        &claim.envelope_epoch.to_be_bytes(),
        &claim.payload_valid_from.to_be_bytes(),
        &claim.payload_expires_at.to_be_bytes(),
        &claim.payload_epoch.to_be_bytes(),
        claim.promotion.as_bytes(),
        claim.command.as_bytes(),
    ];
    let mut transcript = Vec::new();
    for field in fields {
        transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    transcript.extend_from_slice(&claim.revision.to_be_bytes());
    transcript.extend_from_slice(&claim.fingerprint);
    Sha256::digest(transcript).into()
}

fn framed_sha256(fields: &[&[u8]]) -> [u8; 32] {
    let mut transcript = Vec::new();
    for field in fields {
        transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
        transcript.extend_from_slice(field);
    }
    Sha256::digest(transcript).into()
}

const fn kind_name(value: runne_promotion_contracts::CanonicalPayloadKind) -> &'static str {
    match value {
        runne_promotion_contracts::CanonicalPayloadKind::Rc1Decision => "rc1",
        runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => "rc2",
        runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => "rc3",
    }
}

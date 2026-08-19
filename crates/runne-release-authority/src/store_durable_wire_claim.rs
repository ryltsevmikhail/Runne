use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageClaimWire {
    pub(super) nonce: String,
    pub(super) envelope: String,
    pub(super) payload: String,
    pub(super) bootstrap: String,
    pub(super) role: String,
    pub(super) promotion: String,
    pub(super) revision: u64,
    pub(super) command: String,
    pub(super) kind: String,
    pub(super) fingerprint: String,
    pub(super) admission_fingerprint: String,
    pub(super) bootstrap_not_before: String,
    pub(super) bootstrap_expires_at: String,
    pub(super) root_epoch: u64,
    pub(super) envelope_not_before: String,
    pub(super) envelope_expires_at: String,
    pub(super) envelope_epoch: u64,
    pub(super) payload_valid_from: u64,
    pub(super) payload_expires_at: u64,
    pub(super) payload_epoch: u64,
    pub(super) role_floor: u64,
}

pub(super) fn stage_claims(record: &crate::store_machine::Record) -> Vec<StageClaimWire> {
    record
        .stage_claims
        .values()
        .map(|x| StageClaimWire {
            nonce: x.nonce.clone(),
            envelope: crate::threshold_fixture_wire::hex(&x.envelope),
            payload: crate::threshold_fixture_wire::hex(&x.payload),
            bootstrap: crate::threshold_fixture_wire::hex(&x.bootstrap),
            role: x.role.clone(),
            promotion: x.promotion.clone(),
            revision: x.revision,
            command: x.command.clone(),
            kind: stage_kind(x.kind).into(),
            fingerprint: crate::threshold_fixture_wire::hex(&x.fingerprint),
            admission_fingerprint: crate::threshold_fixture_wire::hex(&x.admission_fingerprint),
            bootstrap_not_before: x.bootstrap_not_before.clone(),
            bootstrap_expires_at: x.bootstrap_expires_at.clone(),
            root_epoch: x.root_epoch,
            envelope_not_before: x.envelope_not_before.clone(),
            envelope_expires_at: x.envelope_expires_at.clone(),
            envelope_epoch: x.envelope_epoch,
            payload_valid_from: x.payload_valid_from,
            payload_expires_at: x.payload_expires_at,
            payload_epoch: x.payload_epoch,
            role_floor: x.role_floor,
        })
        .collect()
}

const fn stage_kind(value: runne_promotion_contracts::CanonicalPayloadKind) -> &'static str {
    match value {
        runne_promotion_contracts::CanonicalPayloadKind::Rc1Decision => "rc1",
        runne_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => "rc2",
        runne_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => "rc3",
    }
}

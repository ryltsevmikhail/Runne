//! Deterministic typed identity derivation for durable V5 admissions.

use sha2::{Digest, Sha256};

use crate::{
    CommandIdentity, OutcomeIdentity, PersistedAdmission, PromotionIdentity, ReservationIdentity,
    RevisionIdentity,
};

#[derive(Clone, Copy)]
pub struct IdentityInput<'a> {
    pub receipt_sha256: [u8; 32],
    pub trust_config_sha256: &'a str,
    pub trust_generation: u64,
    pub receipt_generation: u64,
    pub allowlist_generation: u64,
    pub payload_schema_id: &'a str,
    pub payload_schema_sha256: [u8; 32],
    pub nonce: &'a str,
    pub envelope_sha256: [u8; 32],
    pub payload_sha256: [u8; 32],
}

pub fn identities(
    input: IdentityInput<'_>,
) -> (
    PromotionIdentity,
    RevisionIdentity,
    CommandIdentity,
    PersistedAdmission,
) {
    let promotion = PromotionIdentity {
        receipt_sha256: input.receipt_sha256,
        trust_config_sha256: input.trust_config_sha256.into(),
    };
    let revision = RevisionIdentity {
        trust_generation: input.trust_generation,
        receipt_generation: input.receipt_generation,
        allowlist_generation: input.allowlist_generation,
        payload_schema_id: input.payload_schema_id.into(),
        payload_schema_sha256: input.payload_schema_sha256,
    };
    let command = CommandIdentity {
        nonce: input.nonce.into(),
        envelope_sha256: input.envelope_sha256,
        payload_sha256: input.payload_sha256,
    };
    let reservation = ReservationIdentity(hash(
        b"runne.owner.v5.reservation/1",
        &[
            &input.receipt_sha256,
            &input.envelope_sha256,
            &input.payload_schema_sha256,
        ],
        input.nonce,
    ));
    let outcome = OutcomeIdentity(hash(
        b"runne.owner.v5.outcome/1",
        &[
            &input.payload_sha256,
            &input.envelope_sha256,
            &input.payload_schema_sha256,
        ],
        input.nonce,
    ));
    (
        promotion,
        revision,
        command,
        PersistedAdmission {
            reservation,
            outcome,
        },
    )
}

fn hash(domain: &[u8], digests: &[&[u8; 32]], nonce: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for digest in digests {
        hash.update(digest);
    }
    hash.update(nonce.as_bytes());
    hash.finalize().into()
}

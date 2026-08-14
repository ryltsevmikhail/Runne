use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::{receipt_v5_wire_tests::support, v5_envelope_test_support::*};

pub fn receipt() -> crate::PrevalidatedPromotionAuthorityReceiptV5 {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = support::trust(&root, [1; 32]);
    let predecessor =
        support::predecessor(&support::subject(), crate::trust_canonical::hex(&[1; 32]));
    let value = support::receipt(&trust);
    let bytes = support::signed_bytes(&root, &value);
    crate::prevalidate_promotion_authority_receipt_v5(
        &bytes,
        Sha256::digest(&bytes).into(),
        &trust,
        &predecessor,
        &support::expected(&value),
    )
    .unwrap()
}

pub fn stage() -> crate::PrevalidatedStageEnvelopeV2 {
    let chain = chain();
    let (value, key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let bytes = signed_stage_v2(&value, &key);
    crate::prevalidate_stage_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
    )
    .unwrap()
}

pub fn evidence() -> crate::PrevalidatedEvidenceEnvelopeV2 {
    let chain = chain();
    let (value, key) = evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let bytes = signed_evidence_v2(&value, &key);
    crate::prevalidate_evidence_envelope_v2(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.receipt5,
    )
    .unwrap()
}

pub fn allowlist() -> crate::PrevalidatedDestinationAllowlistV1 {
    let chain = chain();
    let value = super::v5_envelope_test_support::allowlist(&chain.trust);
    let unsigned = crate::canonical_unsigned_allowlist_v1(&value).unwrap();
    let receipt = allowlist_receipt5(&chain.root, &chain.trust, Sha256::digest(&unsigned).into());
    let bytes = signed_allowlist_v1(&value, &chain.root);
    crate::prevalidate_destination_allowlist_v1(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &chain.trust,
        &receipt,
    )
    .unwrap()
}

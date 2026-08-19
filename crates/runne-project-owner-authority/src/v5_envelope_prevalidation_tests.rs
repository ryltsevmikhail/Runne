use sha2::{Digest, Sha256};

use crate::v5_envelope_test_support::*;
use crate::{
    prevalidate_destination_allowlist_v1, prevalidate_evidence_envelope_v2,
    prevalidate_stage_envelope_v2,
};

#[test]
fn v5_envelope_prevalidation_accepts_the_raw_chain_without_context() {
    let chain = chain();
    let (stage, stage_key) = stage_envelope(&chain.receipt5, "RC3_PUBLICATION_AUTHORIZER");
    let stage_bytes = signed_stage_v2(&stage, &stage_key);
    assert!(
        prevalidate_stage_envelope_v2(
            &stage_bytes,
            Sha256::digest(&stage_bytes[..stage_bytes.len() - 1]).into(),
            &chain.receipt5,
        )
        .is_ok()
    );
    let (evidence, evidence_key) =
        evidence_envelope(&chain.receipt5, "RC3_FINAL_REVIEWER", "final-review");
    let evidence_bytes = signed_evidence_v2(&evidence, &evidence_key);
    assert!(
        prevalidate_evidence_envelope_v2(
            &evidence_bytes,
            Sha256::digest(&evidence_bytes[..evidence_bytes.len() - 1]).into(),
            &chain.receipt5,
        )
        .is_ok()
    );
    let allowlist = allowlist(&chain.trust);
    let unsigned = crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap();
    let receipt5 = allowlist_receipt5(&chain.root, &chain.trust, Sha256::digest(&unsigned).into());
    let allowlist_bytes = signed_allowlist_v1(&allowlist, &chain.root);
    assert!(
        prevalidate_destination_allowlist_v1(
            &allowlist_bytes,
            Sha256::digest(&allowlist_bytes[..allowlist_bytes.len() - 1]).into(),
            &chain.trust,
            &receipt5,
        )
        .is_ok()
    );
}

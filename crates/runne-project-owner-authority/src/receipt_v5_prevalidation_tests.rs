#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::{ExpectedReceiptV5Bindings, prevalidate_promotion_authority_receipt_v5};

use crate::receipt_v5_wire_tests::support;

#[test]
fn receipt_v5_prevalidation_performs_no_context_admission() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = support::trust(&root, [1; 32]);
    let predecessor =
        support::predecessor(&support::subject(), crate::trust_canonical::hex(&[1; 32]));
    let value = support::receipt(&trust);
    let bytes = support::signed_bytes(&root, &value);
    let expected = ExpectedReceiptV5Bindings::test_only(
        value.production_security_review_sha256,
        value.subject.clone(),
        value.destination_allowlist_sha256,
        value.destination_allowlist_generation,
    );

    assert!(
        prevalidate_promotion_authority_receipt_v5(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &expected,
        )
        .is_ok()
    );
}

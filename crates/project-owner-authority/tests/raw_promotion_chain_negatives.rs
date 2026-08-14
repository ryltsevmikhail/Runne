//! Fail-closed raw promotion bootstrap vectors.

use ed25519_dalek::Signer as _;
use gocode_project_owner_authority::{
    AuthorityError, RECEIPT_SCHEMA_V4, SigningDomain, canonical_checked_in_promotion_bootstrap,
    canonical_unsigned_promotion_bootstrap, signing_transcript, verify_promotion_bootstrap_bytes,
};
use sha2::{Digest, Sha256};

mod raw_promotion_support;
use raw_promotion_support::{BootstrapContext, chain::signed_bootstrap};

#[test]
fn raw_bootstrap_rejects_digest_predecessor_pins_and_signature_mutations() {
    let (root_key, trust, predecessor, signed) = signed_bootstrap();
    let bytes =
        canonical_checked_in_promotion_bootstrap(&signed.unsigned, &signed.signature).unwrap();
    let mut wrong_digest = signed.project_owner_authority_receipt_sha256;
    wrong_digest[0] ^= 1;
    assert_eq!(
        verify_promotion_bootstrap_bytes(
            &bytes,
            wrong_digest,
            &trust,
            &predecessor,
            &BootstrapContext::valid(),
        ),
        Err(AuthorityError::InvalidReceiptDigest)
    );

    let mut wrong_predecessor = signed.unsigned.clone();
    wrong_predecessor.predecessor_receipt_sha256[0] ^= 1;
    let domain = SigningDomain::new(
        RECEIPT_SCHEMA_V4,
        "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP",
        "gocode",
    )
    .unwrap();
    let signature = root_key
        .sign(&signing_transcript(
            &domain,
            &canonical_unsigned_promotion_bootstrap(&wrong_predecessor).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_promotion_bootstrap(&wrong_predecessor, &signature).unwrap();
    assert_eq!(
        verify_promotion_bootstrap_bytes(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &BootstrapContext::valid(),
        ),
        Err(AuthorityError::InvalidReceiptTrust)
    );

    let bytes = canonical_checked_in_promotion_bootstrap(&signed.unsigned, &[0; 64]).unwrap();
    assert_eq!(
        verify_promotion_bootstrap_bytes(
            &bytes,
            Sha256::digest(&bytes).into(),
            &trust,
            &predecessor,
            &BootstrapContext::valid(),
        ),
        Err(AuthorityError::InvalidReceiptSignature)
    );
}

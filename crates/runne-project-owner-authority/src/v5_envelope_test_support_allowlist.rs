use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::{VerifiedPromotionBootstrapV5, trust_canonical::hex};

pub fn allowlist_receipt5(
    root: &SigningKey,
    trust: &crate::VerifiedTrustConfigV4,
    digest: [u8; 32],
) -> VerifiedPromotionBootstrapV5 {
    let predecessor = super::v5_envelope_test_support_chain::predecessor(
        &super::v5_envelope_test_support_chain::subject(),
        hex(&[1; 32]),
    );
    let mut receipt = super::v5_envelope_test_support_chain::receipt(trust);
    receipt.destination_allowlist_sha256 = digest;
    let bytes = super::v5_envelope_test_support_chain::signed_bytes(root, &receipt);
    crate::verify_promotion_authority_receipt_v5(
        &bytes,
        Sha256::digest(&bytes).into(),
        trust,
        &predecessor,
        &crate::ExpectedReceiptV5Bindings::test_only(
            receipt.production_security_review_sha256,
            receipt.subject.clone(),
            digest,
            receipt.destination_allowlist_generation,
        ),
        &super::Receipt5Context(std::cell::Cell::new(0)),
    )
    .expect("real verifier must accept a matching synthetic allowlist binding")
}

pub fn allowlist(trust: &crate::VerifiedTrustConfigV4) -> crate::PublicationDestinationAllowlistV1 {
    crate::PublicationDestinationAllowlistV1 {
        schema_version: crate::DESTINATION_ALLOWLIST_SCHEMA_V1.into(),
        repository_id: "runne".into(),
        generation: 1,
        policy_id: "rc3-publication-policy".into(),
        destinations: vec![crate::PublicationDestinationV1 {
            destination: "github".into(),
            channel: "release-notes".into(),
            permitted_effect_kinds: vec!["notify".into(), "upload".into()],
            executor_policy_sha256: [7; 32],
        }],
        issued_at: "2026-01-01T00:00:00Z".into(),
        not_before: "2026-01-01T00:00:01Z".into(),
        expires_at: "2026-01-01T00:00:05Z".into(),
        revocation_epoch: 1,
        key_id: hex(&crate::key_id(&trust.public_key)),
        key_epoch: trust.epoch,
        signature: String::new(),
    }
}

pub fn signed_allowlist_v1(
    allowlist: &crate::PublicationDestinationAllowlistV1,
    root: &SigningKey,
) -> Vec<u8> {
    let signature = root
        .sign(
            &crate::framed_transcript(
                b"runne.project-owner.publication-destination-allowlist/1",
                &crate::canonical_unsigned_allowlist_v1(allowlist).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    crate::canonical_checked_in_allowlist_v1(allowlist, &signature).unwrap()
}

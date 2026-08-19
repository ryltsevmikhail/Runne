use std::cell::Cell;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::receipt_v5_wire_tests::support;
use crate::v5_envelope_test_support::{allowlist, signed_allowlist_v1};

struct ReviewContext;
impl crate::ProductionSecurityReviewVerificationContext for ReviewContext {
    fn verify_production_security_review(&self, _: &[u8]) -> Result<(), crate::AuthorityError> {
        Ok(())
    }
}
struct SubjectContext(crate::GitSubject);
impl crate::GitSubjectResolutionContext for SubjectContext {
    fn resolve_git_subject(&self) -> Result<crate::GitSubject, crate::AuthorityError> {
        Ok(self.0.clone())
    }
}

#[test]
fn opaque_independent_inputs_produce_expectations_and_all_mismatches_precede_context() {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = support::trust(&root, [1; 32]);
    let predecessor =
        support::predecessor(&support::subject(), crate::trust_canonical::hex(&[1; 32]));
    let review_bytes =
        br#"{"repository_id":"runne","schema_version":"runne.rc0.production-security-review/1"}"#;
    let review =
        crate::verify_production_security_review_instance(review_bytes, &ReviewContext).unwrap();
    let mut different_subject = support::subject();
    different_subject.commit_oid.replace_range(..1, "f");
    assert_eq!(
        crate::resolve_git_subject(&predecessor, &SubjectContext(different_subject)),
        Err(crate::AuthorityError::InvalidReceiptTrust)
    );
    let subject =
        crate::resolve_git_subject(&predecessor, &SubjectContext(support::subject())).unwrap();
    let allowlist = allowlist(&trust);
    let unsigned = crate::canonical_unsigned_allowlist_v1(&allowlist).unwrap();
    let bytes = signed_allowlist_v1(&allowlist, &root);
    let allowlist = crate::prevalidate_root_signed_destination_allowlist_v1(
        &bytes,
        Sha256::digest(&bytes[..bytes.len() - 1]).into(),
        &trust,
    )
    .unwrap();
    let expected = crate::expected_receipt_v5_bindings(&review, &subject, &allowlist);
    let mut value = support::receipt(&trust);
    value.production_security_review_sha256 = Sha256::digest(review_bytes).into();
    value.destination_allowlist_sha256 = Sha256::digest(unsigned).into();
    let valid = support::signed_bytes(&root, &value);
    let context = support::Context(Cell::new(0));
    crate::verify_promotion_authority_receipt_v5(
        &valid,
        Sha256::digest(&valid).into(),
        &trust,
        &predecessor,
        &expected,
        &context,
    )
    .unwrap();
    assert_eq!(context.0.get(), 1);

    for mutation in 0..4 {
        let mut changed = value.clone();
        match mutation {
            0 => changed.production_security_review_sha256[0] ^= 1,
            1 => changed.subject.commit_oid.replace_range(..1, "f"),
            2 => changed.destination_allowlist_sha256[0] ^= 1,
            _ => changed.destination_allowlist_generation += 1,
        }
        let bytes = support::signed_bytes(&root, &changed);
        let context = support::Context(Cell::new(0));
        assert_eq!(
            crate::verify_promotion_authority_receipt_v5(
                &bytes,
                Sha256::digest(&bytes).into(),
                &trust,
                &predecessor,
                &expected,
                &context,
            ),
            Err(crate::AuthorityError::InvalidReceiptTrust)
        );
        assert_eq!(context.0.get(), 0);
    }
}

//! Durable root-bootstrap admission and recovery vectors.

use std::cell::{Cell, RefCell};

use ed25519_dalek::Signer as _;
use runne_project_owner_authority::{
    AuthorityError, PromotionBootstrapAdmission, PromotionBootstrapAdmissionScope,
    PromotionBootstrapValidity, PromotionBootstrapVerificationContext,
    PromotionBootstrapVerificationState, RECEIPT_SCHEMA_V4, SignedPromotionBootstrapV4,
    SigningDomain, canonical_checked_in_promotion_bootstrap,
    canonical_unsigned_promotion_bootstrap, signing_transcript, verify_promotion_bootstrap_bytes,
};
use sha2::{Digest, Sha256};

mod raw_promotion_support;
use raw_promotion_support::chain::signed_bootstrap;

struct Context {
    now: Cell<&'static str>,
    revocation: Cell<u64>,
    read_generation: Cell<u64>,
    current_generation: Cell<u64>,
    admitted: RefCell<Option<([u8; 32], PromotionBootstrapAdmissionScope)>>,
}
impl Context {
    const fn valid() -> Self {
        Self {
            now: Cell::new("2026-08-13T00:00:03Z"),
            revocation: Cell::new(1),
            read_generation: Cell::new(7),
            current_generation: Cell::new(7),
            admitted: RefCell::new(None),
        }
    }
}
impl PromotionBootstrapVerificationContext for Context {
    fn authority_store_profile(&self) -> Result<&str, AuthorityError> {
        Ok("store-1")
    }
    fn read_state(&self) -> Result<PromotionBootstrapVerificationState, AuthorityError> {
        Ok(PromotionBootstrapVerificationState {
            revocation_epoch: self.revocation.get(),
            generation: self.read_generation.get(),
        })
    }

    fn admit_or_recover_bootstrap(
        &self,
        expected: &PromotionBootstrapVerificationState,
        digest: [u8; 32],
        scope: &PromotionBootstrapAdmissionScope,
        validity: &PromotionBootstrapValidity,
    ) -> Result<PromotionBootstrapAdmission, AuthorityError> {
        if let Some((admitted_digest, admitted_scope)) = self.admitted.borrow().as_ref() {
            return if *admitted_digest == digest && admitted_scope == scope {
                if expected.revocation_epoch == scope.root_revocation_epoch() {
                    Ok(PromotionBootstrapAdmission::ExistingSame)
                } else {
                    Err(AuthorityError::StaleOrRevokedPromotionBootstrap)
                }
            } else {
                Err(AuthorityError::PromotionBootstrapAdmissionConflict)
            };
        }
        if expected.generation != self.current_generation.get() {
            return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
        }
        if expected.revocation_epoch != scope.root_revocation_epoch()
            || validity.issued_at() > self.now.get()
            || validity.not_before() > self.now.get()
            || validity.expires_at() <= self.now.get()
        {
            return Err(AuthorityError::StaleOrRevokedPromotionBootstrap);
        }
        *self.admitted.borrow_mut() = Some((digest, scope.clone()));
        Ok(PromotionBootstrapAdmission::NewlyAdmitted)
    }
}

fn verify(
    signed: &SignedPromotionBootstrapV4,
    trust: &runne_project_owner_authority::VerifiedTrustConfigV3,
    predecessor: &runne_project_owner_authority::VerifiedDocumentReconciliation,
    context: &Context,
) -> Result<runne_project_owner_authority::VerifiedPromotionBootstrap, AuthorityError> {
    let bytes = canonical_checked_in_promotion_bootstrap(&signed.unsigned, &signed.signature)?;
    verify_promotion_bootstrap_bytes(
        &bytes,
        signed.project_owner_authority_receipt_sha256,
        trust,
        predecessor,
        context,
    )
}

#[test]
fn exact_crash_recovery_survives_expiry_but_retains_verified_scope() {
    let (_, trust, predecessor, signed) = signed_bootstrap();
    let context = Context::valid();
    let first = verify(&signed, &trust, &predecessor, &context).unwrap();
    assert_eq!(first.validity().expires_at(), "2026-08-13T00:00:04Z");
    assert_eq!(first.admission_scope().root_revocation_epoch(), 1);
    context.now.set("2026-08-13T00:00:04Z");
    let recovered = verify(&signed, &trust, &predecessor, &context).unwrap();
    assert_eq!(first.receipt_sha256(), recovered.receipt_sha256());
    context.revocation.set(2);
    assert_eq!(
        verify(&signed, &trust, &predecessor, &context),
        Err(AuthorityError::StaleOrRevokedPromotionBootstrap)
    );
}

#[test]
fn new_bootstrap_rejects_future_stale_revoked_and_generation_races() {
    let (_, trust, predecessor, signed) = signed_bootstrap();
    for (now, revocation, generation, expected) in [
        (
            "2026-08-13T00:00:00Z",
            1,
            7,
            AuthorityError::StaleOrRevokedPromotionBootstrap,
        ),
        (
            "2026-08-13T00:00:04Z",
            1,
            7,
            AuthorityError::StaleOrRevokedPromotionBootstrap,
        ),
        (
            "2026-08-13T00:00:03Z",
            2,
            7,
            AuthorityError::StaleOrRevokedPromotionBootstrap,
        ),
        (
            "2026-08-13T00:00:03Z",
            1,
            8,
            AuthorityError::PromotionBootstrapAdmissionConflict,
        ),
    ] {
        let context = Context::valid();
        context.now.set(now);
        context.revocation.set(revocation);
        context.current_generation.set(generation);
        assert_eq!(
            verify(&signed, &trust, &predecessor, &context),
            Err(expected)
        );
    }
}

#[test]
fn admitted_lineage_cannot_resume_a_different_valid_digest() {
    let (root, trust, predecessor, signed) = signed_bootstrap();
    let context = Context::valid();
    verify(&signed, &trust, &predecessor, &context).unwrap();
    let mut changed = signed.unsigned;
    changed.promotion_policy_revision = "policy-2".into();
    let domain = SigningDomain::new(
        RECEIPT_SCHEMA_V4,
        "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP",
        "runne",
    )
    .unwrap();
    let signature = root
        .sign(&signing_transcript(
            &domain,
            &canonical_unsigned_promotion_bootstrap(&changed).unwrap(),
        ))
        .to_bytes();
    let bytes = canonical_checked_in_promotion_bootstrap(&changed, &signature).unwrap();
    let divergent = SignedPromotionBootstrapV4 {
        project_owner_authority_receipt_sha256: Sha256::digest(&bytes).into(),
        unsigned: changed,
        signature,
    };
    assert_eq!(
        verify(&divergent, &trust, &predecessor, &context),
        Err(AuthorityError::PromotionBootstrapAdmissionConflict)
    );
}

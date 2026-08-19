#![cfg(feature = "fixture-only")]

use ed25519_dalek::SigningKey;
use runne_release_authority::{
    AuthorityError, FixtureEvidenceKeyRegistration, FixtureEvidenceTrustState,
};

#[path = "canonical_wire/admission_support.rs"]
mod admission_support;
#[path = "canonical_wire/metadata_support.rs"]
mod metadata_support;
#[path = "verify_signed/support.rs"]
mod signing_support;
#[path = "canonical_wire/support.rs"]
mod support;
mod verified_stage_support;

#[test]
fn raw_signing_effect_uses_the_store_owned_trust_snapshot() {
    let (mut store, id, payloads) = signing_support::signing_authorized();
    let (authorization, _record, claim) = signing_support::first_signing_effect_claim(&payloads);
    let wrong_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let trust = FixtureEvidenceTrustState::try_new(
        1,
        1,
        2,
        vec![FixtureEvidenceKeyRegistration::new(
            "signer-principal",
            "signer-account",
            "signer-lane",
            "signer-key",
            "signer-profile",
            wrong_key,
        )],
    )
    .unwrap();
    store.set_rc2_evidence_trust_snapshot(&id, &trust).unwrap();
    let lease = store
        .reserve_rc2_signing_effects(&id, 4)
        .unwrap()
        .take("linux-appimage")
        .unwrap();
    assert_eq!(
        store.verify_rc2_signing_effect_with_lease(&id, claim, &authorization, lease,),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn trust_state_rejects_ambiguous_roles_and_nonpositive_generations() {
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let registration = |role: &str, key_id: &str, public_key| {
        FixtureEvidenceKeyRegistration::new(
            &format!("{role}-principal"),
            &format!("{role}-account"),
            &format!("{role}-lane"),
            key_id,
            &format!("{role}-profile"),
            public_key,
        )
    };
    assert_eq!(
        FixtureEvidenceTrustState::try_new(1, 0, 1, vec![]),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(
        FixtureEvidenceTrustState::try_new(1, 1, 0, vec![]),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(
        FixtureEvidenceTrustState::try_new(
            1,
            1,
            1,
            vec![
                registration("signer", "one", key),
                registration("runner", "two", key)
            ],
        ),
        Err(AuthorityError::BindingMismatch)
    );
    assert_eq!(
        FixtureEvidenceTrustState::try_new(
            1,
            1,
            1,
            vec![
                registration("signer", "one", key),
                registration("runner", "one", [8; 32])
            ],
        ),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn replacing_a_registered_key_requires_a_new_trust_generation() {
    let (mut store, id, _) = signing_support::signing_authorized();
    let replacement = FixtureEvidenceTrustState::try_new(
        1,
        1,
        1,
        vec![FixtureEvidenceKeyRegistration::new(
            "signer-principal",
            "signer-account",
            "signer-lane",
            "signer-key",
            "signer-profile",
            SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
        )],
    )
    .unwrap();
    assert_eq!(
        store.set_rc2_evidence_trust_snapshot(&id, &replacement),
        Err(AuthorityError::BindingMismatch)
    );
}

#[test]
fn trust_snapshot_rejects_same_generation_and_clearing_registered_keys() {
    let (mut store, id, _) = signing_support::signing_authorized();
    assert_eq!(
        store.set_rc2_evidence_trust_snapshot(&id, &signing_support::trust_snapshot(1, 1, 1)),
        Err(AuthorityError::BindingMismatch)
    );
    store
        .set_rc2_evidence_trust_snapshot(&id, &signing_support::trust_snapshot(1, 1, 2))
        .unwrap();
    let clear = FixtureEvidenceTrustState::try_new(1, 1, 3, vec![]).unwrap();
    assert_eq!(
        store.set_rc2_evidence_trust_snapshot(&id, &clear),
        Err(AuthorityError::BindingMismatch)
    );
}

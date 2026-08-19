use ed25519_dalek::{Signer, SigningKey};
use runne_project_owner_authority::{
    AuthorityError, TrustAnchorState, after_explicit_compromise_declaration,
    canonical_genesis_without_pop, framed_transcript, rotation_new_pop_payload,
    rotation_old_authorization_payload, verify_active_trust_config, verify_rotation,
    verify_rotation_chain,
};

mod rotation_support;
use rotation_support::{NEW_DOMAIN, OLD_DOMAIN, genesis, rotation, rotation_with_seed};

#[test]
fn verifies_old_authorization_and_new_pop_then_produces_active_successor() {
    let old = genesis();
    let rotation = rotation(&old);
    let successor = verify_rotation(&old, &rotation).expect("verified rotation");

    assert_eq!(successor.epoch, 2);
    assert_eq!(successor.predecessor, Some(old.sha256().expect("old sha")));
    assert_eq!(successor.key_id, rotation.new_key_id);
    assert_eq!(successor.public_key, rotation.new_public_key);
    assert_eq!(
        successor.proof_of_possession,
        rotation.new_proof_of_possession
    );
}

#[test]
fn transcript_vectors_are_hand_authored_and_domains_are_not_substitutable() {
    assert_eq!(
        framed_transcript(OLD_DOMAIN, b"{}"),
        Ok([
            &48_u32.to_be_bytes()[..],
            OLD_DOMAIN,
            &2_u64.to_be_bytes(),
            b"{}",
        ]
        .concat())
    );
    assert_eq!(
        framed_transcript(NEW_DOMAIN, b"{}"),
        Ok([
            &54_u32.to_be_bytes()[..],
            NEW_DOMAIN,
            &2_u64.to_be_bytes(),
            b"{}",
        ]
        .concat())
    );
    assert_ne!(
        framed_transcript(OLD_DOMAIN, b"{}"),
        framed_transcript(NEW_DOMAIN, b"{}")
    );
}

#[test]
fn old_authorization_binds_the_new_pop_and_rejects_substitution() {
    let old = genesis();
    let candidate = rotation(&old);
    let other = rotation_with_seed(&old, [9; 32]);
    let mut mixed = other;
    mixed.old_authorization = candidate.old_authorization;
    assert_eq!(
        verify_rotation(&old, &mixed),
        Err(AuthorityError::InvalidRotationOldAuthorization)
    );
}

#[test]
fn rejects_old_only_new_only_skipped_predecessor_and_domain_mismatches() {
    let old = genesis();
    let valid = rotation(&old);
    let mut old_only = valid.clone();
    old_only.new_proof_of_possession = [0; 64];
    assert_eq!(
        verify_rotation(&old, &old_only),
        Err(AuthorityError::InvalidRotationNewPop)
    );
    let mut new_only = valid.clone();
    new_only.old_authorization = [0; 64];
    assert_eq!(
        verify_rotation(&old, &new_only),
        Err(AuthorityError::InvalidRotationOldAuthorization)
    );
    let mut skipped = valid.clone();
    skipped.new_epoch += 1;
    assert_eq!(
        verify_rotation(&old, &skipped),
        Err(AuthorityError::InvalidRotationEpoch)
    );
    let mut predecessor = valid.clone();
    predecessor.predecessor_config_sha256 = [0; 32];
    assert_eq!(
        verify_rotation(&old, &predecessor),
        Err(AuthorityError::InvalidRotationPredecessor)
    );
    let mut domain = valid;
    domain.old_authorization = SigningKey::from_bytes(&[7; 32])
        .sign(
            &framed_transcript(
                NEW_DOMAIN,
                &rotation_old_authorization_payload(&domain).expect("payload"),
            )
            .expect("frame"),
        )
        .to_bytes();
    assert_eq!(
        verify_rotation(&old, &domain),
        Err(AuthorityError::InvalidRotationOldAuthorization)
    );
}

#[test]
fn rejects_reused_keys_and_full_chain_aba_reuse() {
    let old = genesis();
    let mut same_key = rotation(&old);
    same_key.new_key_id = old.key_id;
    same_key.new_public_key = old.public_key;
    assert_eq!(
        verify_rotation(&old, &same_key),
        Err(AuthorityError::InvalidRotationKey)
    );

    let first = rotation(&old);
    let successor = verify_rotation(&old, &first).expect("first successor");
    let mut aba = rotation(&successor);
    aba.new_key_id = old.key_id;
    aba.new_public_key = old.public_key;
    let returned_key = SigningKey::from_bytes(&[7; 32]);
    aba.new_proof_of_possession = returned_key
        .sign(
            &framed_transcript(
                NEW_DOMAIN,
                &rotation_new_pop_payload(&successor, &aba).expect("payload"),
            )
            .expect("frame"),
        )
        .to_bytes();
    let old_key = SigningKey::from_bytes(&[8; 32]);
    aba.old_authorization = old_key
        .sign(
            &framed_transcript(
                OLD_DOMAIN,
                &rotation_old_authorization_payload(&aba).expect("payload"),
            )
            .expect("frame"),
        )
        .to_bytes();
    assert_eq!(
        verify_rotation_chain(
            &old,
            &[first, aba],
            &TrustAnchorState::confirmed("runne".into(), 1, old.sha256().expect("sha"))
        ),
        Err(AuthorityError::ReusedRotationKey)
    );
}

#[test]
fn chain_rejects_final_rollback_and_fork_against_local_anchor() {
    let old = genesis();
    let first = rotation(&old);
    let successor = verify_rotation(&old, &first).expect("successor");
    assert_eq!(
        verify_rotation_chain(
            &old,
            std::slice::from_ref(&first),
            &TrustAnchorState::confirmed("runne".into(), 3, [0; 32]),
        ),
        Err(AuthorityError::TrustEpochRollback)
    );
    assert_eq!(
        verify_rotation_chain(
            &old,
            &[first],
            &TrustAnchorState::confirmed("runne".into(), 2, [0; 32]),
        ),
        Err(AuthorityError::TrustConfigFork)
    );
    assert_eq!(
        verify_rotation_chain(
            &old,
            &[rotation(&old)],
            &TrustAnchorState::confirmed("runne".into(), 2, successor.sha256().expect("sha")),
        )
        .map(|config| config.epoch),
        Ok(2)
    );
}

#[test]
fn rotation_rejects_unproved_predecessor_and_zero_anchor_floor() {
    let old = genesis();
    let mut unproved = old.clone();
    unproved.proof_of_possession = [0; 64];
    assert!(verify_rotation(&unproved, &rotation(&old)).is_err());

    assert_eq!(
        verify_rotation_chain(
            &old,
            &[],
            &TrustAnchorState::confirmed("runne".into(), 0, [0; 32]),
        ),
        Err(AuthorityError::InvalidTrustAnchor)
    );
}

#[test]
fn active_trust_rejects_a_self_signed_epoch_zero_successor_shape() {
    let mut zero = genesis();
    zero.epoch = 0;
    zero.predecessor = Some([1; 32]);
    zero.proof_of_possession = SigningKey::from_bytes(&[7; 32])
        .sign(
            &framed_transcript(
                NEW_DOMAIN,
                &canonical_genesis_without_pop(&zero).expect("canonical zero epoch"),
            )
            .expect("frame"),
        )
        .to_bytes();
    assert_eq!(
        verify_active_trust_config(&zero),
        Err(AuthorityError::InvalidGenesis)
    );
}

#[test]
fn chain_requires_the_pinned_config_at_the_anchor_epoch() {
    let old = genesis();
    let anchor = TrustAnchorState::confirmed("runne".into(), 1, old.sha256().expect("sha"));
    let mut fork = old;
    fork.schema_digests[0].schema_sha256 = [4; 32];
    fork.proof_of_possession = SigningKey::from_bytes(&[7; 32])
        .sign(
            &framed_transcript(
                b"runne.project-owner.genesis-pop/1",
                &canonical_genesis_without_pop(&fork).expect("canonical genesis"),
            )
            .expect("frame"),
        )
        .to_bytes();
    assert_eq!(
        verify_rotation_chain(&fork, &[rotation(&fork)], &anchor),
        Err(AuthorityError::TrustConfigFork)
    );
}

#[test]
fn compromise_reset_is_explicit_and_invalid_rotation_never_infers_it() {
    let old = genesis();
    let mut invalid = rotation(&old);
    invalid.new_epoch += 1;
    assert_eq!(
        verify_rotation(&old, &invalid),
        Err(AuthorityError::InvalidRotationEpoch)
    );
    let reset = after_explicit_compromise_declaration(&old);
    assert_eq!(reset.repository_id, "runne");
    assert_eq!(reset.compromised_key_id, old.key_id);
    assert_eq!(reset.compromised_epoch, 1);
}

use super::{PayloadKind, open, seal};
use crate::{BoundedCanonicalId, MutationIdentity, MutationOperation, MutationTargetKind};
use runne_secure_store::{SecureStore, test_support::DeterministicSecureStore};

fn identity(key: &str) -> MutationIdentity {
    MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ConversationGenerateText,
        MutationTargetKind::Conversation,
        BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000081").unwrap(),
        key,
        4,
        [3; 32],
    )
    .unwrap()
}

#[test]
fn encrypted_payload_binds_profile_database_full_mutation_identity_and_kind() {
    let profile = [4; 32];
    let database = [5; 32];
    let secure = DeterministicSecureStore::new(profile);
    let lock = secure.acquire_security_profile_lock(profile).unwrap();
    let command_identity = identity("intent-a");
    let plaintext = b"synthetic known secret input";
    let reference = crate::security_ledger_v7::digest::command(plaintext);
    let stored = seal(
        &lock,
        profile,
        database,
        &command_identity,
        PayloadKind::Command,
        plaintext,
    )
    .unwrap();
    assert!(stored.starts_with(b"RNV9"));
    assert_eq!(
        open(
            &lock,
            profile,
            database,
            &command_identity,
            PayloadKind::Command,
            &stored,
            reference.as_bytes()
        )
        .unwrap()
        .as_slice(),
        plaintext
    );
    assert!(
        open(
            &lock,
            [6; 32],
            database,
            &command_identity,
            PayloadKind::Command,
            &stored,
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            [7; 32],
            &command_identity,
            PayloadKind::Command,
            &stored,
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            database,
            &identity("intent-b"),
            PayloadKind::Command,
            &stored,
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            database,
            &command_identity,
            PayloadKind::Outcome,
            &stored,
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            database,
            &command_identity,
            PayloadKind::Command,
            &stored,
            &[8; 32]
        )
        .is_err()
    );
}

#[test]
fn unknown_or_truncated_envelopes_and_legacy_reference_mismatch_fail_closed() {
    let profile = [9; 32];
    let database = [10; 32];
    let secure = DeterministicSecureStore::new(profile);
    let lock = secure.acquire_security_profile_lock(profile).unwrap();
    let identity = identity("intent-c");
    let plaintext = b"synthetic migration payload";
    let reference = crate::security_ledger_v7::digest::command(plaintext);
    let mut unknown = seal(
        &lock,
        profile,
        database,
        &identity,
        PayloadKind::Command,
        plaintext,
    )
    .unwrap();
    unknown[4] = 2;
    assert!(
        open(
            &lock,
            profile,
            database,
            &identity,
            PayloadKind::Command,
            &unknown,
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            database,
            &identity,
            PayloadKind::Command,
            b"RNV9\x01",
            reference.as_bytes()
        )
        .is_err()
    );
    assert!(
        open(
            &lock,
            profile,
            database,
            &identity,
            PayloadKind::Command,
            plaintext,
            &[11; 32]
        )
        .is_err()
    );
    assert_eq!(
        open(
            &lock,
            profile,
            database,
            &identity,
            PayloadKind::Command,
            plaintext,
            reference.as_bytes()
        )
        .unwrap()
        .as_slice(),
        plaintext
    );
}

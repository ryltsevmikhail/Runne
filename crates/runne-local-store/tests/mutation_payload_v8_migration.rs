#![cfg(feature = "test-support")]

use runne_local_store::{
    BoundedCanonicalId, LocalStore, MutationIdentity, MutationOperation, MutationRecoveryBinding,
    MutationRecoveryLimit, MutationTargetKind, NormalizedMutationCommand,
};
use runne_secure_store::{SecureStore, test_support::DeterministicSecureStore};

#[path = "support/mutation_payload_support.rs"]
mod support;
use support::*;

#[test]
fn legacy_v8_command_and_outcome_are_reencrypted_scrubbed_and_downgrade_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy-profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let (legacy_bytes, old_command_ref, old_outcome_ref, logical_outcome) =
        install_legacy_v8_payloads(&path, &secure);

    secure.fail_next_advance();
    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    let mut reopened =
        LocalStore::open_anchored(&path, &secure, PROFILE).expect("resume committed v9 migration");
    let binding = MutationRecoveryBinding::new(RUNTIME, PRINCIPAL).unwrap();
    let recovered = reopened
        .recover_anchored_mutations_v7(&secure, binding, MutationRecoveryLimit::new(1).unwrap())
        .unwrap();
    assert_eq!(recovered.records()[0].normalized_command(), &command());
    let terminal = reopened
        .prepare_anchored_mutation_v7(
            &secure,
            identity_with("legacy-outcome", [216; 32]),
            command(),
        )
        .unwrap();
    assert_eq!(terminal.record().normalized_command(), Some(&command()));
    assert_eq!(
        terminal.record().canonical_outcome(),
        Some(&logical_outcome)
    );
    let retained: Vec<u8> = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT normalized_command FROM mutation_ledger WHERE idempotency_key='legacy-outcome'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained.starts_with(b"RNV9"));
    assert_ne!(retained, legacy_bytes);
    let (retained_outcome, command_ref, outcome_ref): (Vec<u8>, Vec<u8>, Vec<u8>) =
        rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
            "SELECT canonical_outcome,command_ref,outcome_ref FROM mutation_ledger WHERE idempotency_key='legacy-outcome'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert!(retained_outcome.starts_with(b"RNV9"));
    assert_eq!(command_ref, old_command_ref);
    assert_eq!(outcome_ref, old_outcome_ref);
    assert_no_input_in_sqlite_family(&path);

    let new_identity = MutationIdentity::new(
        RUNTIME,
        PRINCIPAL,
        MutationOperation::ConversationGenerateText,
        MutationTargetKind::Conversation,
        BoundedCanonicalId::parse(CONVERSATION.as_bytes()).unwrap(),
        "new-encrypted-input",
        4,
        [215; 32],
    )
    .unwrap();
    let new_command = NormalizedMutationCommand::GenerateText {
        conversation_id: BoundedCanonicalId::parse(CONVERSATION.as_bytes()).unwrap(),
        expected_version: 4,
        text: "synthetic clean follow-up input".into(),
    };
    reopened
        .prepare_anchored_mutation_v7(&secure, new_identity, new_command)
        .unwrap();
    let new_payload: Vec<u8> = rusqlite::Connection::open(&path).unwrap()
        .query_row("SELECT normalized_command FROM mutation_ledger WHERE idempotency_key='new-encrypted-input'", [], |row| row.get(0)).unwrap();
    assert!(new_payload.starts_with(b"RNV9"));
    let before = secure
        .read_security_anchor(&secure.acquire_security_profile_lock(PROFILE).unwrap())
        .unwrap();
    drop(reopened);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA user_version=8; UPDATE meta SET schema_version=8;")
        .unwrap();
    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    let lock = secure.acquire_security_profile_lock(PROFILE).unwrap();
    assert_eq!(secure.read_security_anchor(&lock).unwrap(), before);
}

#[test]
fn interruption_after_scrub_retries_before_v9_fence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("scrub-retry.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let mut store = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity("scrub-retry"), command())
        .unwrap();
    runne_local_store::security_open_test_support::downgrade_to_v8_for_test(
        &mut store, &secure, "",
    )
    .unwrap();
    drop(store);

    runne_local_store::security_open_test_support::fail_after_v8_payload_scrub_once_for_test();
    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 8);
    assert_no_input_in_sqlite_family(&path);
    let mut reopened = LocalStore::open_anchored(&path, &secure, PROFILE)
        .expect("repeat authenticated scrub, then install v9 fence");
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 9);
    assert_no_input_in_sqlite_family(&path);
    assert_eq!(
        reopened
            .recover_anchored_mutations_v7(
                &secure,
                MutationRecoveryBinding::new(RUNTIME, PRINCIPAL).unwrap(),
                MutationRecoveryLimit::new(1).unwrap(),
            )
            .unwrap()
            .records()[0]
            .normalized_command(),
        &command()
    );
}

#[test]
fn busy_checkpoint_keeps_v8_retryable_and_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("busy-retry.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let mut store = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity("busy-retry"), command())
        .unwrap();
    runne_local_store::security_open_test_support::downgrade_to_v8_for_test(
        &mut store, &secure, "",
    )
    .unwrap();
    drop(store);
    let reader =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    reader
        .execute_batch("BEGIN; SELECT normalized_command FROM mutation_ledger;")
        .unwrap();

    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 8);
    drop(reader);
    let _reopened = LocalStore::open_anchored(&path, &secure, PROFILE)
        .expect("retry checkpoint after the external reader exits");
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 9);
    assert_no_input_in_sqlite_family(&path);
}

#[test]
fn interrupted_v7_to_v8_anchor_advance_is_recovered_before_v9_encryption_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v7-profile.sqlite3");
    let secure = DeterministicSecureStore::new(PROFILE);
    let mut store = LocalStore::open_anchored(&path, &secure, PROFILE).unwrap();
    store
        .prepare_anchored_mutation_v7(&secure, identity("v7-legacy-input"), command())
        .unwrap();
    let legacy_bytes = command().encode().unwrap();
    let sql = format!(
        "UPDATE mutation_ledger SET normalized_command=x'{}' WHERE idempotency_key='v7-legacy-input'",
        hex(&legacy_bytes)
    );
    runne_local_store::security_open_test_support::downgrade_to_v7_for_test(
        &mut store, &secure, &sql,
    )
    .unwrap();
    drop(store);

    secure.fail_next_advance();
    assert!(LocalStore::open_anchored(&path, &secure, PROFILE).is_err());
    let mut reopened = LocalStore::open_anchored(&path, &secure, PROFILE)
        .expect("recover committed v8 anchor before sealing the v9 writer fence");
    let evidence = reopened
        .recover_anchored_mutations_v7(
            &secure,
            MutationRecoveryBinding::new(RUNTIME, PRINCIPAL).unwrap(),
            MutationRecoveryLimit::new(1).unwrap(),
        )
        .unwrap();
    assert_eq!(evidence.records()[0].normalized_command(), &command());
}

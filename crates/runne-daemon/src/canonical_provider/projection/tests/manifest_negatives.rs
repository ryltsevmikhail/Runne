use super::*;
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::RuntimeAuthorityId;
use runne_domain::conversation::GenerationFailureReason;
use runne_domain::message::MessageText;

#[test]
fn text_path_manifest_binds_identity_and_order() {
    let (_directory, database_path) = text_path_database("d13-manifest-identity");
    let authority = RuntimeAuthorityId("d13-manifest-identity".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let first = seed_started_conversation(&store, authority, 1, "same input");
    let digest_first = project_text_path(&store, &first)
        .unwrap()
        .manifest_digest()
        .to_owned();
    assert_eq!(
        project_text_path(&store, &first).unwrap().manifest_digest(),
        &digest_first
    );
    let second = seed_started_conversation(
        &store,
        RuntimeAuthorityId("d13-manifest-identity".into()),
        2,
        "same input",
    );
    let digest_second = project_text_path(&store, &second)
        .unwrap()
        .manifest_digest()
        .to_owned();
    assert_ne!(digest_second, digest_first);
}

#[test]
fn tampered_committed_digest_rejects_projection() {
    let (_directory, database_path) = text_path_database("d13-tampered-digest");
    let authority = RuntimeAuthorityId("d13-tampered-digest".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let seed = seed_started_conversation(&store, authority.clone(), 1, "hello");
    // Positive control: the untampered seeded store projects successfully.
    project_text_path(&store, &seed).unwrap();
    drop(store);
    let reopened = reopen_after_tamper(
        &database_path,
        authority,
        seed.started.conversation_id,
        "UPDATE events SET integrity_digest = x'ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB'
         WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
    );
    assert_eq!(
        project_text_path(&reopened, &seed),
        Err(CanonicalProviderExecutionError::Unavailable)
    );
}

#[test]
fn deleted_committed_event_rejects_projection() {
    let (_directory, database_path) = text_path_database("d13-deleted-event");
    let authority = RuntimeAuthorityId("d13-deleted-event".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let seed = seed_started_conversation(&store, authority.clone(), 1, "hello");
    // Positive control: the untampered seeded store projects successfully.
    project_text_path(&store, &seed).unwrap();
    drop(store);
    let reopened = reopen_after_tamper(
        &database_path,
        authority,
        seed.started.conversation_id,
        "DELETE FROM events WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
    );
    assert_eq!(
        project_text_path(&reopened, &seed),
        Err(CanonicalProviderExecutionError::Unavailable)
    );
}

#[test]
fn swapped_adjacent_digests_reject_projection() {
    let (_directory, database_path) = text_path_database("d13-swapped-digests");
    let authority = RuntimeAuthorityId("d13-swapped-digests".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let seed = seed_started_conversation(&store, authority.clone(), 1, "hello");
    // Positive control: the untampered seeded store projects successfully
    // (before the finish/swap setup moves the conversation version).
    project_text_path(&store, &seed).unwrap();
    let service = ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority.clone(),
        text_path_guard(),
    );
    service
        .finish(
            &seed.context,
            FinishConversationTextInput {
                original: seed.original.clone(),
                started: seed.started.clone(),
                completion: ConversationTextCompletion::Rejected {
                    reason: GenerationFailureReason::ProviderOutputRejected,
                },
            },
        )
        .unwrap();
    drop(service);
    drop(store);
    let conversation_id = seed.started.conversation_id;
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let digests: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT
                (SELECT integrity_digest FROM events
                 WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1),
                (SELECT integrity_digest FROM events
                 WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 2)",
            rusqlite::params![conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE events SET integrity_digest = ?2
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 1",
            rusqlite::params![conversation_id.as_bytes(), digests.1],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE events SET integrity_digest = ?2
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = 2",
            rusqlite::params![conversation_id.as_bytes(), digests.0],
        )
        .unwrap();
    drop(connection);
    let reopened = StoreTransaction::open(&database_path, authority, text_path_guard()).unwrap();
    assert_eq!(
        project_text_path(&reopened, &seed),
        Err(CanonicalProviderExecutionError::Unavailable)
    );
}

#[test]
fn stale_conversation_version_rejects_projection_with_conflict() {
    let (_directory, database_path) = text_path_database("d13-stale-version");
    let authority = RuntimeAuthorityId("d13-stale-version".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), text_path_guard()).unwrap();
    let seed = seed_started_conversation(&store, authority.clone(), 1, "hello");
    let service =
        ConversationTextService::new(store.clone(), store.clone(), authority, text_path_guard());
    let rejected = service
        .finish(
            &seed.context,
            FinishConversationTextInput {
                original: seed.original.clone(),
                started: seed.started.clone(),
                completion: ConversationTextCompletion::Rejected {
                    reason: GenerationFailureReason::ProviderOutputRejected,
                },
            },
        )
        .unwrap();
    assert_eq!(
        rejected.conversation_version,
        seed.started.conversation_version + 1
    );
    service
        .begin(
            &text_path_context(5, "generate-text-replacement"),
            BeginConversationTextInput {
                conversation_id: seed.original.conversation_id,
                expected_version: rejected.conversation_version,
                text: MessageText::new("hello again").unwrap(),
            },
        )
        .unwrap();
    assert_eq!(
        project_text_path(&store, &seed),
        Err(CanonicalProviderExecutionError::Conflict)
    );
}

use runne_api::CreateConversationInput;
use runne_application::commands::BeginConversationTextInput;
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::{
    ProviderEncryptedPayload, ProviderJournalKeyBinding, ProviderTerminalOutboxRecord,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use runne_domain::message::MessageText;
use runne_provider::{DispatchAttemptId, ProviderCallDigestVersion};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderTerminalConversationResolver,
    ProviderTerminalOutboxApplication,
};
use runne_security::SecretBroker;
use runne_store::schema::apply_migrations;
use runne_store::store::StoreTransaction;
use rusqlite::Connection;
use std::sync::Arc;
#[path = "support/v36_receipt_downgrade.rs"]
mod v36_receipt_downgrade;
#[path = "support/v37_accounting_downgrade.rs"]
mod v37_accounting_downgrade;
#[path = "support/v39_lineage_downgrade.rs"]
mod v39_lineage_downgrade;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;
fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn assert_reopen_rejected(database: &std::path::Path) {
    assert!(
        StoreTransaction::open(
            database.to_str().unwrap(),
            RuntimeAuthorityId("provider-conversation-terminal".into()),
            available_guard(),
        )
        .is_err()
    );
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("test").unwrap(),
    }
}

#[test]
fn production_terminal_application_reconstructs_started_command_and_finishes_once() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join("provider-conversation-terminal.sqlite");
    let authority = RuntimeAuthorityId("provider-conversation-terminal".into());
    let store = StoreTransaction::open(
        database.to_str().unwrap(),
        authority.clone(),
        available_guard(),
    )
    .unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000081".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000082".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let create_context = context(
        "018f2e3a-7000-7000-8000-000000000083",
        "create-provider-conversation",
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let old_projection: (Vec<u8>, Vec<u8>, Vec<u8>) = Connection::open(&database)
        .unwrap()
        .query_row(
            "SELECT projection_bytes, projection_digest, snapshot_integrity_digest
             FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let generate_context = context(
        "018f2e3a-7000-7000-8000-000000000084",
        "generate-provider-conversation",
    );
    let service: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority,
        available_guard(),
    ));
    let started = service
        .begin_text(
            &generate_context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("hello provider").unwrap(),
            },
        )
        .unwrap();
    let record = ProviderTerminalOutboxRecord {
        outbox_id: [31; 16],
        attempt_id: DispatchAttemptId::from_bytes([32; 16]),
        fencing_token: 1,
        principal_id: "local-owner".into(),
        conversation_id,
        taskrun_id: started.taskrun_id,
        execution_attempt_id: started.attempt_id,
        terminal_sequence: 3,
        call_digest_version: ProviderCallDigestVersion::V2,
        key: ProviderJournalKeyBinding::new([33; 16], 1, [34; 16], 1).unwrap(),
        encrypted_output: ProviderEncryptedPayload::new([35; 12], vec![36; 17], 1, [37; 32])
            .unwrap(),
        runtime_generation: 1,
        profile_digest: [38; 32],
        settlement_digest: [39; 32],
        application_idempotency_key: "provider-terminal-attempt-1".into(),
    };
    let recovered = store
        .resolve_provider_terminal_conversation(&record)
        .unwrap();
    assert_eq!(recovered.original.expected_version, 1);
    assert_eq!(recovered.original.text.as_str(), "hello provider");
    assert_eq!(recovered.started, started);
    let application = ConversationProviderTerminalApplication::new(store.clone(), service);
    let first = application
        .complete_provider_terminal(&record, b"provider answer")
        .unwrap();
    let replay = application
        .complete_provider_terminal(&record, b"provider answer")
        .unwrap();
    assert_ne!(first, [0; 32]);
    assert_eq!(replay, first);
    let stream = store.load_conversation(conversation_id).unwrap();
    assert_eq!(stream.current_version, 3);
    assert_eq!(
        stream
            .events
            .iter()
            .filter(|event| matches!(
                event.payload(),
                ConversationEvent::AssistantMessageAppended { .. }
            ))
            .count(),
        1
    );
    drop(store);
    let connection = Connection::open(&database).unwrap();
    let snapshots: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM aggregate_state_snapshots AS snapshot
             JOIN aggregate_streams AS stream ON stream.aggregate_type = snapshot.aggregate_type
                AND stream.aggregate_id = snapshot.aggregate_id
             WHERE snapshot.aggregate_version = stream.current_version
                AND snapshot.event_sequence = stream.current_version
                AND snapshot.head_event_id = stream.last_event_id",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(snapshots, 2);
    connection
        .execute_batch(
            "DROP TABLE IF EXISTS provider_qualification_admission_fences; DROP TABLE IF EXISTS credential_cleanup_recovery_attempts; DROP TRIGGER IF EXISTS aggregate_state_snapshots_bind_insert;
             DROP TRIGGER IF EXISTS aggregate_state_snapshots_bind_update;
             DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_insert;
             DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_update;
             DROP TRIGGER IF EXISTS schema_v12_fence_aggregate_state_snapshots_delete;
             DROP INDEX IF EXISTS idx_aggregate_state_snapshots_head_position;
             DROP TABLE IF EXISTS aggregate_state_snapshots;
             DROP TABLE IF EXISTS process_output;
             DROP INDEX IF EXISTS idx_process_registry_owner;
             DROP TABLE IF EXISTS process_registry;
             DROP INDEX IF EXISTS idx_approvals_pending;
             DROP TABLE IF EXISTS approvals; DROP TABLE IF EXISTS provider_online_credential_effect_bindings; DROP TABLE IF EXISTS provider_online_dispatch_claim_providers; DROP TABLE IF EXISTS provider_online_dispatch_issuance_evidence; DROP TABLE IF EXISTS provider_credential_completion_receipts; DROP TABLE IF EXISTS provider_credential_process_attachments; DROP TABLE IF EXISTS provider_credential_operations; DROP TABLE IF EXISTS provider_credential_ticket_attempts; DROP TABLE IF EXISTS provider_credential_authority_heads; DROP TABLE IF EXISTS provider_credential_readiness_observations; DROP TABLE IF EXISTS provider_credential_verification_observations; DROP TABLE IF EXISTS provider_subscription_budgets;
             DROP TABLE IF EXISTS conversation_context_scope;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_delete;
         DELETE FROM schema_version WHERE version >= 19;",
    )
        .unwrap();
    v37_accounting_downgrade::restore_v36_accounting(&connection).unwrap();
    v36_receipt_downgrade::restore_v18_receipt(&connection).unwrap();
    v39_lineage_downgrade::restore_v18_lineage(&connection).unwrap();
    apply_migrations(&connection).unwrap();
    let backfilled: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM aggregate_state_snapshots",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(backfilled, 2);
    let projection_bytes: Vec<u8> = connection
        .query_row(
            "SELECT projection_bytes FROM aggregate_state_snapshots
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = x'00'
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = ?1
             WHERE aggregate_type = 2 AND aggregate_id = ?2",
            rusqlite::params![projection_bytes, conversation_id.as_bytes()],
        )
        .unwrap();
    let snapshot_integrity_digest: Vec<u8> = connection
        .query_row(
            "SELECT snapshot_integrity_digest FROM aggregate_state_snapshots
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET projection_bytes = ?1, projection_digest = ?2,
             snapshot_integrity_digest = ?3 WHERE aggregate_type = 2 AND aggregate_id = ?4",
            rusqlite::params![
                old_projection.0,
                old_projection.1,
                old_projection.2,
                conversation_id.as_bytes()
            ],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = zeroblob(32)
             WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = ?1
             WHERE aggregate_type = 2 AND aggregate_id = ?2",
            rusqlite::params![snapshot_integrity_digest, conversation_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_reopen_rejected(&database);
}

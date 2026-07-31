use std::sync::Arc;

use gocode_application::commands::{CommandOutcome, CreateTaskRunInput};
use gocode_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::service::TaskRunService;
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_provider::{ProviderCallDigestVersion, ProviderCallId};
use gocode_security::SecretBroker;
use gocode_store::provider::{
    PersistPreparedOutcome, PreparedProviderRecord, SqliteProviderDispatchStore,
};
use gocode_store::schema::{SchemaRollbackError, rollback_pre_v12_snapshot};
use gocode_store::store::StoreTransaction;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn command_context() -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: CommandId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
        ]),
        idempotency_key: IdempotencyKey::new("rollback-unavailable-taskrun").unwrap(),
        principal_id: PrincipalId("test-principal".to_owned()),
        actor: Actor::new("test-actor").unwrap(),
    }
}

#[test]
fn rollback_without_atomic_cutover_is_unavailable_to_open_store_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("authoritative.sqlite");
    let authority = RuntimeAuthorityId("test-runtime-authority".to_owned());
    let application_store =
        StoreTransaction::open(path.to_str().unwrap(), authority.clone(), available_guard())
            .unwrap();
    let provider_store = SqliteProviderDispatchStore::open(&path).unwrap();

    assert_eq!(
        rollback_pre_v12_snapshot(&path),
        Err(SchemaRollbackError::AuthoritySwitchUnavailable)
    );

    assert_eq!(
        provider_store
            .persist_prepared(&PreparedProviderRecord {
                call_id: ProviderCallId::from_bytes([1; 16]),
                call_digest_version: ProviderCallDigestVersion::V2,
                prepared_digest: [2; 32],
                render_digest: [3; 32],
                profile_digest: [4; 32],
            })
            .unwrap(),
        PersistPreparedOutcome::Inserted
    );

    let service = TaskRunService::new(
        application_store.clone(),
        application_store.clone(),
        application_store,
        authority,
    );
    let outcome = service
        .create_task_run(
            &command_context(),
            CreateTaskRunInput {
                conversation_id: "018f2e3a-7000-7000-8000-00000000000a"
                    .parse::<ConversationId>()
                    .unwrap(),
                workspace_id: "018f2e3a-7000-7000-8000-00000000000b"
                    .parse::<WorkspaceId>()
                    .unwrap(),
            },
        )
        .unwrap();
    assert!(matches!(outcome, CommandOutcome::TaskRunCreated { .. }));

    let verification = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        verification
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        12
    );
    assert_eq!(
        verification
            .query_row(
                "SELECT COUNT(*) FROM provider_prepared_requests",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        verification
            .query_row("SELECT COUNT(*) FROM aggregate_streams", [], |row| row
                .get::<_, i64>(0),)
            .unwrap(),
        1
    );
}

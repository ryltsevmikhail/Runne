use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::event::Actor;
use gocode_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;
use rusqlite::Connection;

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn fixture(
    label: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ConversationId,
    StoreTransaction,
) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database = daemon.join(format!("{label}.sqlite"));
    let authority = RuntimeAuthorityId(format!("snapshot-binding-{label}"));
    let store =
        StoreTransaction::open(database.to_str().unwrap(), authority.clone(), guard()).unwrap();
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-0000000000b1".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-0000000000b2".parse().unwrap();
    validated_reopen::seed_canonical_workspace(&store, "local-owner", workspace_id);
    let context = ApplicationCommandContext {
        command_id: "018f2e3a-7000-7000-8000-0000000000b3".parse().unwrap(),
        idempotency_key: IdempotencyKey::new("snapshot-binding-create").unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("snapshot-binding").unwrap(),
    };
    ConversationService::new(store.clone(), store.clone(), authority)
        .create_from_application(
            &context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
            },
        )
        .unwrap();
    (directory, database, conversation_id, store)
}

#[test]
fn v17_database_constraints_and_head_trigger_reject_every_structural_snapshot_binding() {
    let (_directory, database, _conversation_id, _store) = fixture("structural");
    let connection = Connection::open(database).unwrap();
    for mutation in [
        "UPDATE aggregate_state_snapshots SET aggregate_type = 1",
        "UPDATE aggregate_state_snapshots SET aggregate_id = zeroblob(16)",
        "UPDATE aggregate_state_snapshots SET codec_version = 2",
        "UPDATE aggregate_state_snapshots SET aggregate_version = 2",
        "UPDATE aggregate_state_snapshots SET event_sequence = 2",
        "UPDATE aggregate_state_snapshots SET head_event_id = zeroblob(16)",
        "UPDATE aggregate_state_snapshots SET head_integrity_digest = zeroblob(32)",
        "UPDATE aggregate_state_snapshots SET head_global_position = 2",
    ] {
        assert!(
            connection.execute_batch(mutation).is_err(),
            "must reject {mutation}"
        );
    }
}

#[test]
fn v17_startup_rejects_each_authenticated_projection_field_after_persistence_tamper() {
    for (label, mutation) in [
        (
            "bytes",
            "UPDATE aggregate_state_snapshots SET projection_bytes = x'00'",
        ),
        (
            "digest",
            "UPDATE aggregate_state_snapshots SET projection_digest = zeroblob(32)",
        ),
        (
            "snapshot-digest",
            "UPDATE aggregate_state_snapshots SET snapshot_integrity_digest = zeroblob(32)",
        ),
    ] {
        let (_directory, database, _conversation_id, store) = fixture(label);
        Connection::open(&database)
            .unwrap()
            .execute_batch(mutation)
            .unwrap();
        drop(store);
        assert!(
            StoreTransaction::open(
                database.to_str().unwrap(),
                RuntimeAuthorityId(format!("snapshot-binding-{label}")),
                guard()
            )
            .is_err(),
            "must reject {label}"
        );
    }
}

use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::CreateTaskRunInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
use gocode_application::service::TaskRunService;
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_security::SecretBroker;
use gocode_store::store::StoreTransaction;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("fixture-test".into()),
        actor: Actor::new("fixture-test").unwrap(),
    }
}

#[test]
fn current_writers_emit_only_taskrun_v1_and_conversation_v2() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon.join("writers.sqlite");
    let authority = RuntimeAuthorityId("fixture-writer".into());
    let store = StoreTransaction::open(path.to_str().unwrap(), authority.clone(), available_guard()).unwrap();
    let taskrun = TaskRunService::new(store.clone(), store.clone(), store.clone(), authority.clone());
    taskrun.create_task_run(&context("018f2e3a-7000-7000-8000-000000000011", "taskrun"), CreateTaskRunInput {
        conversation_id: "018f2e3a-7000-7000-8000-000000000012".parse::<ConversationId>().unwrap(),
        workspace_id: "018f2e3a-7000-7000-8000-000000000013".parse::<WorkspaceId>().unwrap(),
    }).unwrap();
    let conversation = ConversationService::new(store.clone(), store.clone(), authority);
    let command_id = "018f2e3a-7000-7000-8000-000000000014".parse::<CommandId>().unwrap();
    let conversation_context = context("018f2e3a-7000-7000-8000-000000000014", "conversation");
    conversation.create_from_application(&conversation_context, CreateConversationInput {
        conversation_id: "018f2e3a-7000-7000-8000-000000000015".parse::<ConversationId>().unwrap(),
        workspace_id: "018f2e3a-7000-7000-8000-000000000016".parse::<WorkspaceId>().unwrap(),
        command_id,
        idempotency_key: conversation_context.idempotency_key.clone(),
    }).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let profiles = connection.prepare("SELECT aggregate_type, integrity_profile FROM events ORDER BY aggregate_type").unwrap().query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(profiles, vec![(1, 1), (2, 2)]);
}

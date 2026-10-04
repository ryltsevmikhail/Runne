use super::super::claim::node_registration;
use super::super::support::*;
use super::online_credentials;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
    SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ExecutionNodeId, ProjectWorkspaceRepository, TaskRunAssignmentIdentity,
};
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::sync::Arc;

#[path = "dispatch.rs"]
pub(super) mod dispatch;
pub(super) use dispatch::dispatch_unknown;

pub(super) struct Fixture {
    pub database: Database,
    pub credentials: SqliteProviderCredentialLifecycleStore,
    pub execution: Arc<runne_store::provider::SqliteProviderExecutionStore>,
    pub launch: runne_store::provider::ProviderRuntimeLaunchCapability,
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub claim_identity: TaskRunAssignmentIdentity,
    pub version: u64,
}

pub(super) fn running(name: &str, tail: u8) -> Fixture {
    running_inner(name, tail, None, true)
}

pub(super) fn running_without_provider_admission(name: &str, tail: u8) -> Fixture {
    running_inner(name, tail, None, false)
}

pub(super) fn running_with_remote_id(name: &str, tail: u8, response_id: &str) -> Fixture {
    running_inner(name, tail, Some(response_id), true)
}

pub(super) fn runtime_authority() -> runne_application::ports::RuntimeAuthorityId {
    runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into())
}

fn running_inner(name: &str, tail: u8, response_id: Option<&str>, admit: bool) -> Fixture {
    let authority = runtime_authority();
    let database = Database::new_with_database_authority(name, authority.clone(), [1; 16]);
    let repository = database.repository();
    repository
        .create_project(
            "principal-1",
            command(1),
            &key("unknown-successor-project"),
            project(PROJECT, "Successor test"),
        )
        .unwrap();
    repository
        .create_workspace(
            "principal-1",
            command(2),
            &key("unknown-successor-workspace"),
            workspace(WORKSPACE, PROJECT, "Successor workspace"),
        )
        .unwrap();
    let conversation_id = ConversationId::from_bytes(command(tail + 0x10).into_bytes());
    ConversationService::new(
        database.store.clone(),
        database.store.clone(),
        authority.clone(),
    )
    .create_from_application(
        &context(tail + 0x20, "unknown-successor-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(tail + 0x20),
            idempotency_key: key("unknown-successor-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let input = TaskRunInput::new("successor fixture request".into())
        .unwrap()
        .with_requested_model("fixture-model".into())
        .unwrap()
        .with_selected_profile(
            SelectedProviderProfile::new("fixture-profile-v1".into(), [2; 32]).unwrap(),
        )
        .unwrap();
    let outcome = TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        authority.clone(),
    )
    .submit_task_run(
        &context(tail, "unknown-successor-submit"),
        SubmitTaskRunInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            input,
        },
    )
    .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submitted TaskRun expected")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claim_context = context(tail + 1, "unknown-successor-claim");
    let runne_application::ports::TaskRunClaimResult::Committed(claim) = TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        authority.clone(),
    )
    .claim_task_run(
        &claim_context,
        ClaimTaskRunInput {
            taskrun_id,
            expected_version: 2,
            node_id: ExecutionNodeId(node_id.clone()),
            node_epoch,
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 30_000,
        },
        &database.store,
    )
    .unwrap() else {
        panic!("claim expected")
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: claim.fence,
    };
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority,
        guard(),
    );
    text.begin_claimed_text(
        &context(tail + 2, "unknown-successor-generation"),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("successor fixture request").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            assignment: identity.clone(),
        },
    )
    .unwrap();
    let credential_connection =
        crate::validated_reopen::open_validated_connection(database.file.path(), database.identity)
            .unwrap();
    let credentials = online_credentials::ready(credential_connection);
    let (execution, launch) = dispatch::runtime_launch(&database);
    if admit {
        if let Some(response_id) = response_id {
            dispatch::dispatch_unknown_with_remote_id(
                &database,
                &credentials,
                &execution,
                &launch,
                &identity,
                conversation_id,
                response_id,
            );
        } else {
            dispatch::dispatch_unknown(
                &database,
                &credentials,
                &execution,
                &launch,
                &identity,
                conversation_id,
            );
        }
    }
    Fixture {
        database,
        credentials,
        execution,
        launch,
        taskrun_id,
        claim_identity: identity,
        version: 4,
    }
}

fn context(tail: u8, key_value: &str) -> runne_application::ports::ApplicationCommandContext {
    runne_application::ports::ApplicationCommandContext {
        command_id: command(tail),
        idempotency_key: key(key_value),
        principal_id: runne_application::ports::PrincipalId("principal-1".into()),
        actor: runne_domain::event::Actor::new("unknown-successor-test").unwrap(),
    }
}

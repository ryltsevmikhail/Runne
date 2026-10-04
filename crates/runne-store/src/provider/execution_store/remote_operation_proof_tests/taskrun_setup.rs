use std::path::Path;

use crate::store::StoreTransaction;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
    SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, ExecutionNodeId, PrincipalId, RuntimeAuthorityId,
    TaskRunAssignmentIdentity, TaskRunClaimResult,
};
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId};
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};

pub(super) struct TestKeyring(pub(super) ProviderJournalKeyRef);

impl ProviderJournalKeyring for TestKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        (key.key_ref() == self.0)
            .then_some(())
            .ok_or(SecureStoreError::CorruptProviderJournalKey)
    }

    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        (key == self.0)
            .then_some(())
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key, [9; 32])
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }

    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if key == self.0 {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }
}

pub(super) fn initialize_identity(path: &Path, authority: [u8; 16]) {
    let connection = super::super::authority_test_support::configured_connection(path);
    crate::schema::ensure_authority_id(&connection, &authority).unwrap();
    crate::schema::ensure_event_log_lineage_id(&connection).unwrap();
}

pub(super) fn submit_and_claim(
    path: &Path,
    authority_bytes: [u8; 16],
) -> (ConversationId, TaskRunId, runne_domain::id::AttemptId) {
    let authority = RuntimeAuthorityId(
        authority_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    );
    let guard = std::sync::Arc::new(runne_security::SecretBroker::new().prohibited_content_guard());
    let writer = super::super::authority_test_support::configured_connection(path);
    let reader = crate::schema::reopen_managed_connection_validated(
        path,
        crate::schema::ConnectionMode::Reader,
        |_| Ok(()),
    )
    .unwrap();
    let store = StoreTransaction::open_with_connections(
        path.to_str().unwrap(),
        writer,
        reader,
        authority.clone(),
        guard,
    )
    .unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000062".parse().unwrap();
    let conversation_id = ConversationId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let conversation_command = command_id();
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &context("remote-proof-conversation", conversation_command),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: conversation_command,
                idempotency_key: IdempotencyKey::new("remote-proof-conversation").unwrap(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let input = TaskRunInput::new("remote proof taskrun".into())
        .unwrap()
        .with_requested_model("fixture-model".into())
        .unwrap()
        .with_selected_profile(
            SelectedProviderProfile::new("background-text-v1".into(), [2; 32]).unwrap(),
        )
        .unwrap();
    let submit = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    )
    .submit_task_run(
        &context("remote-proof-submit", command_id()),
        SubmitTaskRunInput {
            conversation_id,
            workspace_id,
            input,
        },
    )
    .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submit else {
        panic!("v2 TaskRun submit expected")
    };
    let writer = super::super::authority_test_support::configured_connection(path);
    let node = uuid::Uuid::from_bytes(authority_bytes);
    let node_epoch = crate::schema::next_launch_generation(&writer).unwrap();
    crate::execution_node::register_local_linux_node(
        &writer,
        *node.as_bytes(),
        node_epoch,
        crate::execution_node::LinuxNodeDescriptor { capacity: 1 },
        30,
    )
    .unwrap();
    let node_id = ExecutionNodeId(node.to_string());
    let service = TaskRunService::new(store.clone(), store.clone(), store.clone(), authority);
    let claim = service
        .claim_task_run(
            &context("remote-proof-claim", command_id()),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id,
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("fresh TaskRun claim expected")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    ConversationTextService::new(
        store.clone(),
        store.clone(),
        RuntimeAuthorityId(
            authority_bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        std::sync::Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .begin_claimed_text(
        &context("remote-proof-begin", command_id()),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: runne_domain::message::MessageText::new("remote proof taskrun").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id,
            assignment,
        },
    )
    .unwrap();
    (conversation_id, taskrun_id, claim.attempt_id)
}

fn context(name: &str, command_id: CommandId) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id,
        idempotency_key: IdempotencyKey::new(name).unwrap(),
        principal_id: PrincipalId("principal-1".into()),
        actor: Actor::new("remote-operation-proof-test").unwrap(),
    }
}

fn command_id() -> CommandId {
    CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes())
}

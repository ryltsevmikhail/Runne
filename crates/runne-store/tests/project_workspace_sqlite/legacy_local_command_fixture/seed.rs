use runne_api::{ApiPrincipalId, ApprovalCreateCommand, ApprovalRequestHostPort};
use runne_application::conversation_service::ConversationService;
use runne_domain::id::{ApprovalId, ConversationId, InvocationId, TaskRunId, WorkspaceId};
use runne_domain::task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand};
use runne_store::{ProjectWorkspaceStore, store::LocalCommandApprovalBinding};

use super::super::support::*;
use super::PreparedLegacyLocalCommand;
use super::legacy_migration::migrate_pending_seed;

#[derive(Clone, Copy)]
pub(super) struct LegacyFixtureSeed<'a> {
    pub(super) staged_state: &'a str,
    pub(super) include_binding: bool,
    pub(super) include_submit_receipt: bool,
}

impl LegacyFixtureSeed<'static> {
    pub(super) const fn pending() -> Self {
        Self {
            staged_state: "approval_pending",
            include_binding: true,
            include_submit_receipt: true,
        }
    }
}

pub async fn prepare(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
) -> PreparedLegacyLocalCommand {
    prepare_inner(
        name,
        seed,
        approval_tail,
        executable_digest,
        admitted_root_identity,
        false,
        LegacyFixtureSeed::pending(),
    )
    .await
    .expect("valid historical fixture migrates")
}

pub async fn prepare_with_node_authority(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
) -> PreparedLegacyLocalCommand {
    prepare_inner(
        name,
        seed,
        approval_tail,
        executable_digest,
        admitted_root_identity,
        true,
        LegacyFixtureSeed::pending(),
    )
    .await
    .expect("valid historical fixture migrates")
}

pub async fn migration_rejects_fixture(
    name: &str,
    seed: u8,
    approval_tail: u8,
    state: &str,
    include_binding: bool,
    include_submit_receipt: bool,
) -> bool {
    prepare_inner(
        name,
        seed,
        approval_tail,
        [0x31; 32],
        [0x32; 32],
        false,
        LegacyFixtureSeed {
            staged_state: state,
            include_binding,
            include_submit_receipt,
        },
    )
    .await
    .is_err()
}

async fn prepare_inner(
    name: &str,
    seed: u8,
    approval_tail: u8,
    executable_digest: [u8; 32],
    admitted_root_identity: [u8; 32],
    use_node_authority: bool,
    fixture_seed: LegacyFixtureSeed<'_>,
) -> rusqlite::Result<PreparedLegacyLocalCommand> {
    let donor = Database::new(&format!("{name}-donor"));
    let repository = donor.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(seed).into_bytes());
    ConversationService::new(donor.store.clone(), donor.store.clone(), authority())
        .create_from_application(
            &task_context(seed, "legacy-local-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(seed),
                idempotency_key: key("legacy-local-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = local_command();
    let (submit_store, submit_authority) = if use_node_authority {
        let connection = donor.connection();
        let authority_bytes: Vec<u8> = connection
            .query_row(
                "SELECT authority_id FROM _authority WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let node_authority = runne_application::ports::RuntimeAuthorityId(
            uuid::Uuid::from_bytes(authority_bytes.try_into().unwrap()).to_string(),
        );
        drop(connection);
        (
            crate::validated_reopen::reopen_store(
                donor.file.path(),
                donor.identity,
                node_authority.clone(),
                guard(),
            )
            .unwrap(),
            node_authority,
        )
    } else {
        (donor.store.clone(), authority())
    };
    let migration_authority = submit_authority.clone();
    let submitter = runne_application::service::TaskRunService::new(
        submit_store.clone(),
        submit_store.clone(),
        submit_store,
        submit_authority,
    );
    let outcome = submitter
        .submit_task_run(
            &task_context(seed + 1, "legacy-local-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(local.clone())
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted local TaskRun")
    };
    let approval_id = ApprovalId::from_bytes(command(approval_tail).into_bytes());
    let binding = LocalCommandApprovalBinding {
        command_digest: local.intent_digest(),
        executable_digest,
        workspace_version: 1,
        admitted_root_version: 1,
        admitted_root_identity,
        trust_epoch: 1,
        trust_revision: 1,
        source_policy_version: 2,
        command_policy_version: 1,
        approval_id: *approval_id.as_bytes(),
    };
    create_pending_approval(&repository, taskrun_id, &local, approval_id).await;
    let database = migrate_pending_seed(
        &donor,
        taskrun_id,
        approval_id,
        binding,
        name,
        fixture_seed,
        migration_authority,
    )?;
    Ok(PreparedLegacyLocalCommand {
        database,
        taskrun_id,
        local,
        approval_id,
        binding,
    })
}

pub async fn create_pending_approval(
    repository: &ProjectWorkspaceStore,
    taskrun_id: TaskRunId,
    local: &TaskRunLocalCommand,
    approval_id: ApprovalId,
) {
    let request = ApprovalCreateCommand::new(
        approval_id,
        taskrun_id,
        None,
        InvocationId::from_bytes(command(approval_id.as_bytes()[15].wrapping_add(1)).into_bytes()),
        ApiPrincipalId::new("owner").unwrap(),
        "local_command.execute",
        format!(
            "taskrun:{taskrun_id}:workspace:{}",
            WorkspaceId::from_bytes(WORKSPACE)
        ),
        local.intent_digest(),
        2,
        1,
        i64::MAX,
        "reviewed local command",
    )
    .unwrap();
    repository.create_pending_approval(request).await.unwrap();
}

fn local_command() -> TaskRunLocalCommand {
    TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap()
}

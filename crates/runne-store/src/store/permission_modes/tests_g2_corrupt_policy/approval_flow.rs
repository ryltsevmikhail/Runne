use super::fixture::{Fixture, command_id, key};
use crate::ProjectWorkspaceStore;
use runne_api::{
    ApiActor, ApprovalCommandContext, ApprovalCommandHostPort, ApprovalCreateCommand,
    ApprovalDecision, ApprovalDecisionCommand, ApprovalRequestHostPort, ApprovalState,
};
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1, ports::EventStoreError,
    project_trust::LOCAL_COMMAND_POLICY_VERSION,
};
use runne_domain::id::ApprovalId;

pub(super) fn confirm(f: &Fixture, b: &LocalCommandPermissionBindingV1) -> ApprovalId {
    assert!(matches!(
        f.store.admit_local_command_permission(b, None),
        Err(EventStoreError::CorruptData)
    ));
    super::assertions::absent(f);
    let id = ApprovalId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let repository = ProjectWorkspaceStore::from_store(f.store.clone());
    let task = b.assignment().taskrun_id;
    let digest = *b.approval().digest().as_bytes();
    let policy = LOCAL_COMMAND_POLICY_VERSION;
    let command = ApprovalCreateCommand::new(
        id,
        task,
        Some(b.assignment().attempt_id),
        b.invocation_id(),
        f.principal.clone(),
        "local_command.execute",
        format!("taskrun:{task}:workspace:{}", f.scope.workspace_id),
        digest,
        policy,
        1,
        b.approval().expires_at_unix_ms,
        "G2 native fixture logical approval; no human authentication",
    )
    .unwrap();
    let pending = futures::executor::block_on(repository.create_pending_approval(command)).unwrap();
    assert_eq!(pending.state(), ApprovalState::Pending);
    assert_eq!(pending.action_digest(), &digest);
    assert_eq!(pending.task_run_id(), task);
    assert_eq!(pending.attempt_id(), Some(b.assignment().attempt_id));
    assert_eq!(pending.invocation_id(), b.invocation_id());
    assert_eq!(pending.expires_at(), b.approval().expires_at_unix_ms);
    super::assertions::absent(f);
    assert!(matches!(
        f.store.admit_local_command_permission(b, Some(id)),
        Err(EventStoreError::CorruptData)
    ));
    super::assertions::absent(f);
    let context = ApprovalCommandContext {
        command_id: command_id(),
        idempotency_key: key(&format!("g2-confirm-{id}")),
        principal: f.principal.clone(),
        actor: ApiActor::new("test-human").unwrap(),
    };
    let command =
        ApprovalDecisionCommand::new(id, 1, ApprovalDecision::Approve, digest, policy, 1).unwrap();
    let approved =
        futures::executor::block_on(repository.decide_approval(context, command)).unwrap();
    assert_eq!(approved.state(), ApprovalState::Approved);
    super::assertions::absent(f);
    id
}

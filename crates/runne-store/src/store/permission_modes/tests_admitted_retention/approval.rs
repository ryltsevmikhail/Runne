use super::fixture::{Fixture, command_id, key};
use crate::ProjectWorkspaceStore;
use runne_api::{
    ApiActor, ApprovalCommandContext, ApprovalCommandHostPort, ApprovalCreateCommand,
    ApprovalDecision, ApprovalDecisionCommand, ApprovalRequestHostPort, ApprovalState,
};
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION;
use runne_domain::id::ApprovalId;
use sha2::{Digest, Sha256};

// Logical test human confirmation only, not GUI/PAM/native re-authentication.
pub(super) fn confirm(f: &Fixture, b: &LocalCommandPermissionBindingV1) -> ApprovalId {
    confirm_with_label(
        f,
        b,
        "Test confirmation for broad same-user process start; never executed",
    )
}

pub(super) fn confirm_native_fixture(
    f: &Fixture,
    b: &LocalCommandPermissionBindingV1,
) -> ApprovalId {
    confirm_with_label(
        f,
        b,
        "Native effect fixture; logical approval, no human authentication",
    )
}

fn confirm_with_label(f: &Fixture, b: &LocalCommandPermissionBindingV1, label: &str) -> ApprovalId {
    let id = ApprovalId::from_bytes(uuid::Uuid::now_v7().into_bytes());
    let repository = ProjectWorkspaceStore::from_store(f.store.clone());
    let taskrun = b.assignment().taskrun_id;
    let digest = *b.approval().digest().as_bytes();
    let policy = LOCAL_COMMAND_POLICY_VERSION;
    let request = ApprovalCreateCommand::new(
        id,
        taskrun,
        Some(b.assignment().attempt_id),
        b.invocation_id(),
        f.principal.clone(),
        "local_command.execute",
        format!("taskrun:{taskrun}:workspace:{}", f.scope.workspace_id),
        digest,
        policy,
        1,
        b.approval().expires_at_unix_ms,
        label,
    )
    .unwrap();
    let pending = futures::executor::block_on(repository.create_pending_approval(request)).unwrap();
    assert_eq!(pending.state(), ApprovalState::Pending);
    assert_eq!(pending.action_digest(), &digest);
    assert_eq!(pending.expires_at(), b.approval().expires_at_unix_ms);
    assert_eq!(pending.invocation_id(), b.invocation_id());
    assert_eq!(pending.attempt_id(), Some(b.assignment().attempt_id));
    assert_eq!(pending.task_run_id(), taskrun);
    let context = ApprovalCommandContext {
        command_id: command_id(),
        idempotency_key: key(&format!("test-human-confirm-{id}")),
        principal: f.principal.clone(),
        actor: ApiActor::new("test-human").unwrap(),
    };
    let decision =
        ApprovalDecisionCommand::new(id, 1, ApprovalDecision::Approve, digest, policy, 1).unwrap();
    let accepted =
        futures::executor::block_on(repository.decide_approval(context, decision)).unwrap();
    assert_eq!(accepted.state(), ApprovalState::Approved);
    id
}

// Read only freshly owned durable data, never manufacture admission/proof rows.
pub(super) fn durable(f: &Fixture, b: &LocalCommandPermissionBindingV1, id: ApprovalId) -> Vec<u8> {
    let capture = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .expect("original durable capture");
    assert_eq!(capture.canonical_binding_digest, *b.digest().as_bytes());
    let reader = f.store.inner.reader.lock().unwrap();
    let (kind, admission_binding, admission_proof, human_binding, proof, approval_digest, approval_id, at):
        (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) = reader.query_row(
        "SELECT a.admission_kind,a.binding_digest,a.proof_digest,h.binding_digest,h.proof_digest,h.approval_digest,h.approval_id,h.accepted_at
         FROM x2_permission_admission a JOIN x2_permission_human h USING(taskrun_id,attempt_id)
         WHERE a.taskrun_id=?1 AND a.attempt_id=?2",
        rusqlite::params![b.assignment().taskrun_id.as_bytes(), b.assignment().attempt_id.as_bytes()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
    ).unwrap();
    assert_eq!(kind, 2);
    assert_eq!(admission_binding, capture.binding_digest);
    assert_eq!(human_binding, capture.binding_digest);
    assert_eq!(admission_proof, proof);
    assert_eq!(approval_digest, b.approval().digest().as_bytes());
    assert_eq!(approval_id, id.as_bytes());
    assert!(at > 0 && at < b.approval().expires_at_unix_ms);
    // Independently frame the published original proof identity, not a fake token.
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:x2-human-approval-proof:v1\0");
    hash.update(b.assignment().taskrun_id.as_bytes());
    hash.update(b.assignment().attempt_id.as_bytes());
    hash.update(b.digest().as_bytes());
    hash.update(b.approval().digest().as_bytes());
    hash.update(id.as_bytes());
    hash.update(at.to_be_bytes());
    assert_eq!(proof, hash.finalize().as_slice());
    proof
}

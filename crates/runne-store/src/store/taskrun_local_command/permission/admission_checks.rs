use super::{model::now_ms, original_approval_facts::OriginalApprovalFacts};
use runne_application::{
    permission_modes::{
        ContainmentStrategy, FilesystemPosture, LocalCommandPermissionBindingV1, PermissionMode,
    },
    ports::EventStoreError,
    project_trust::{ManagedEffectClass, ManagedEffectDecision},
};
use runne_domain::id::{ApprovalId, TaskRunId};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "tests_cross_mode_data.rs"]
mod cross_mode_data;

type ApprovalRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
);

pub(super) fn verify_original_approval(
    tx: &Transaction<'_>,
    facts: &OriginalApprovalFacts<'_>,
    id: ApprovalId,
    allow_expired: bool,
) -> Result<i64, EventStoreError> {
    let row: Option<ApprovalRow> = tx.query_row(
        "SELECT task_run_id,attempt_id,invocation_id,principal_id,action,resource,action_digest,
                policy_revision,request_version,state,decision,decision_principal_id,decided_at,expires_at
         FROM approvals WHERE approval_id=?1",
        [id.to_string()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,
            row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    let Some(row) = row else {
        return Err(EventStoreError::CorruptData);
    };
    let accepted = row.12.ok_or(EventStoreError::CorruptData)?;
    let taskrun = facts.approval.invocation.task_run_id;
    let attempt = facts.approval.invocation.attempt_id;
    let attempt_text = attempt.to_string();
    let resource = format!(
        "taskrun:{taskrun}:workspace:{}",
        facts.selection.scope.workspace_id
    );
    if row.0 != taskrun.to_string()
        || row.1.as_deref() != Some(attempt_text.as_str())
        || row.2 != facts.approval.invocation.invocation_id.to_string()
        || row.3 != facts.selection.scope.principal_id.as_str()
        || row.4 != "local_command.execute"
        || row.5 != resource
        || row.6.as_slice() != facts.approval.digest().as_bytes()
        || row.7 != runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION as i64
        || row.8 != 2
        || row.9 != 2
        || row.10 != Some(1)
        || row.11.as_deref() != Some(row.3.as_str())
        || row.13 != facts.approval.expires_at_unix_ms
        || accepted <= 0
        || (!allow_expired && row.13 <= now_ms())
        || row.13 <= accepted
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(accepted)
}

pub(super) fn original_proof_digest(
    taskrun: TaskRunId,
    facts: &OriginalApprovalFacts<'_>,
    id: ApprovalId,
    accepted_at: i64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:x2-human-approval-proof:v1\0");
    hash.update(taskrun.as_bytes());
    hash.update(facts.approval.invocation.attempt_id.as_bytes());
    hash.update(&facts.canonical_digest);
    hash.update(facts.approval.digest().as_bytes());
    hash.update(id.as_bytes());
    hash.update(accepted_at.to_be_bytes());
    hash.finalize().into()
}
// Verified historical original data, NOT live/native execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionKind {
    Pending,
    Auto,
    Human,
}
#[derive(Debug)]
pub(super) struct VerifiedOriginalAdmission {
    kind: AdmissionKind,
    expires_at: i64,
}
impl VerifiedOriginalAdmission {
    pub(super) fn live_human(&self, now: i64) -> bool {
        self.kind == AdmissionKind::Human && self.expires_at > now
    }
}

pub(super) fn classify_original_admission(
    tx: &Transaction<'_>,
    capture: &super::read::LocalCommandPermissionCaptureV1,
    facts: &OriginalApprovalFacts<'_>,
    now: i64,
) -> Result<VerifiedOriginalAdmission, EventStoreError> {
    if capture.canonical_binding_digest != facts.canonical_digest
        || capture.taskrun_id != facts.approval.invocation.task_run_id
        || capture.attempt_id != facts.approval.invocation.attempt_id
        || capture.invocation_id != facts.approval.invocation.invocation_id
    {
        return Err(EventStoreError::CorruptData);
    }
    if capture.state == crate::store::LocalCommandAttemptState::ApprovalPending {
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM x2_permission_admission WHERE taskrun_id=?1)
                 OR EXISTS(SELECT 1 FROM x2_permission_human WHERE taskrun_id=?1)",
                [capture.taskrun_id.as_bytes()],
                |r| r.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if exists {
            return Err(EventStoreError::CorruptData);
        }
        return Ok(VerifiedOriginalAdmission {
            kind: AdmissionKind::Pending,
            expires_at: facts.approval.expires_at_unix_ms,
        });
    }
    // Historical expiry is checked independently by live eligibility. Terminal
    // reconciliation must still validate a stopped original after its expiry.
    verify_original_admission(tx, facts, &capture.binding_digest, now, true)
}

pub(super) fn verify_original_admission(
    tx: &rusqlite::Transaction<'_>,
    facts: &OriginalApprovalFacts<'_>,
    digest: &[u8; 32],
    now: i64,
    allow_expired: bool,
) -> Result<VerifiedOriginalAdmission, EventStoreError> {
    let row: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT admission_kind,proof_digest FROM x2_permission_admission
         WHERE taskrun_id=?1 AND attempt_id=?2 AND binding_digest=?3",
            params![
                facts.approval.invocation.task_run_id.as_bytes(),
                facts.approval.invocation.attempt_id.as_bytes(),
                digest.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    match row {
        Some((1, None))
            if facts.selection.selected_mode == PermissionMode::FullAccess
                && facts.scope.filesystem.posture == FilesystemPosture::BroadSameUser
                && matches!(
                    facts.scope.containment,
                    ContainmentStrategy::SameUserCompositeV1
                        | ContainmentStrategy::SameUserCompositeV2
                )
                && facts
                    .snapshot
                    .policy
                    .decision_for(ManagedEffectClass::ProcessStart)
                    == ManagedEffectDecision::Allow
                && facts
                    .scope
                    .managed_policy
                    .scope_minimum_disposition(facts.scope)
                    == Some(ManagedEffectDecision::Allow) =>
        {
            Ok(VerifiedOriginalAdmission {
                kind: AdmissionKind::Auto,
                expires_at: facts.approval.expires_at_unix_ms,
            })
        }
        Some((2, Some(proof))) => {
            let human: (Vec<u8>, Vec<u8>, i64) = tx
                .query_row(
                    "SELECT approval_id,proof_digest,accepted_at FROM x2_permission_human
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND binding_digest=?3",
                    params![
                        facts.approval.invocation.task_run_id.as_bytes(),
                        facts.approval.invocation.attempt_id.as_bytes(),
                        digest.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|_| EventStoreError::CorruptData)?;
            let id = ApprovalId::from_bytes(
                human
                    .0
                    .as_slice()
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            if human.1 != proof
                || proof.as_slice()
                    != original_proof_digest(
                        facts.approval.invocation.task_run_id,
                        facts,
                        id,
                        human.2,
                    )
                    .as_slice()
                || verify_original_approval(tx, facts, id, allow_expired)? != human.2
                || human.2 > now
            {
                return Err(EventStoreError::CorruptData);
            }
            Ok(VerifiedOriginalAdmission {
                kind: AdmissionKind::Human,
                expires_at: facts.approval.expires_at_unix_ms,
            })
        }
        _ => Err(EventStoreError::CorruptData),
    }
}

// Existing binding-taking entrypoints preserve the original proof domain.
pub(super) fn verify_approval(
    tx: &Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
    id: ApprovalId,
    allow_expired: bool,
) -> Result<i64, EventStoreError> {
    verify_original_approval(
        tx,
        &OriginalApprovalFacts::from_binding(binding),
        id,
        allow_expired,
    )
}

pub(super) fn proof_digest(
    taskrun: TaskRunId,
    binding: &LocalCommandPermissionBindingV1,
    id: ApprovalId,
    accepted_at: i64,
) -> [u8; 32] {
    original_proof_digest(
        taskrun,
        &OriginalApprovalFacts::from_binding(binding),
        id,
        accepted_at,
    )
}

pub(super) fn verify_admission(
    tx: &Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
    digest: &[u8; 32],
    now: i64,
    allow_expired: bool,
) -> Result<(), EventStoreError> {
    verify_original_admission(
        tx,
        &OriginalApprovalFacts::from_binding(binding),
        digest,
        now,
        allow_expired,
    )
    .map(|_| ())
}

//! Fixed D2 plan references derived from committed TaskRun and conversation state.
use runne_domain::{
    context::ContextManifestRef,
    id::{
        AttemptId, BudgetReservationId, ContextManifestId, CycleId, IntegrityDigest, PlanId,
        ResultId, TaskRunId,
    },
    plan::PlanRevisionRef,
    reference::{BudgetReservationRef, ResultRef},
};
use sha2::{Digest, Sha256};

pub(super) const POLICY_REVISION: &str = "d2-safe-tool-loop-plan-v1";

/// Constructs immutable references from the exact committed conversation prefix and D2 policy.
// The manifest hashes each identity, stream prefix, source and budget independently.
#[allow(clippy::too_many_arguments)]
pub(super) fn references(
    taskrun: TaskRunId,
    attempt: AttemptId,
    cycle: CycleId,
    conversation_id: runne_domain::id::ConversationId,
    conversation_head: u64,
    event_refs: &[(u64, [u8; 16], IntegrityDigest)],
    taskrun_event_refs: &[(u64, [u8; 16], IntegrityDigest)],
    prompt_digest: IntegrityDigest,
    workspace_version: u64,
    root_revision: u64,
    root_identity: [u8; 32],
    trust_epoch: u64,
    trust_revision: u64,
    profile_digest: [u8; 32],
    schema_digest: IntegrityDigest,
    budget: BudgetReservationRef,
) -> (ContextManifestRef, PlanRevisionRef) {
    let mut context_hash = Sha256::new();
    context_hash.update(b"RUNNE_D2_CONTEXT_V1\0");
    context_hash.update(taskrun.as_bytes());
    context_hash.update(attempt.as_bytes());
    context_hash.update(cycle.as_bytes());
    context_hash.update(conversation_id.as_bytes());
    context_hash.update(conversation_head.to_be_bytes());
    context_hash.update(b"conversation\0");
    for (sequence, event_id, digest) in event_refs {
        context_hash.update(sequence.to_be_bytes());
        context_hash.update(event_id);
        context_hash.update(digest.as_bytes());
    }
    context_hash.update(b"taskrun\0");
    for (sequence, event_id, digest) in taskrun_event_refs {
        context_hash.update(sequence.to_be_bytes());
        context_hash.update(event_id);
        context_hash.update(digest.as_bytes());
    }
    context_hash.update(prompt_digest.as_bytes());
    context_hash.update(workspace_version.to_be_bytes());
    context_hash.update(root_revision.to_be_bytes());
    context_hash.update(root_identity);
    context_hash.update(trust_epoch.to_be_bytes());
    context_hash.update(trust_revision.to_be_bytes());
    context_hash.update(profile_digest);
    let context_digest = digest(context_hash.finalize().into());
    let context = ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(stable_id(
            context_digest.as_bytes(),
            b"manifest",
        )),
        taskrun_id: taskrun,
        attempt_id: attempt,
        cycle_id: cycle,
        revision: conversation_head,
        policy_revision: POLICY_REVISION.into(),
        integrity_digest: context_digest,
    };

    let mut batch_hash = Sha256::new();
    batch_hash.update(b"RUNNE_D2_FIXED_TOOL_BATCH_V1\0");
    batch_hash.update(context_digest.as_bytes());
    batch_hash.update(profile_digest);
    batch_hash.update(schema_digest.as_bytes());
    batch_hash
        .update(b"workspace.file.read\0workspace.file.create_new\0effects=2\0continuations=2");
    let batch_digest = digest(batch_hash.finalize().into());
    let policy_digest = digest(
        Sha256::new()
            .chain_update(b"RUNNE_D2_TOOL_POLICY_V1\0")
            .chain_update(profile_digest)
            .chain_update(schema_digest.as_bytes())
            .finalize()
            .into(),
    );
    let plan_id = PlanId::from_bytes(stable_id(batch_digest.as_bytes(), b"plan"));
    let plan_hash = Sha256::new()
        .chain_update(b"RUNNE_D2_PLAN_REVISION_V1\0")
        .chain_update(taskrun.as_bytes())
        .chain_update(cycle.as_bytes())
        .chain_update(context.integrity_digest.as_bytes())
        .chain_update(batch_digest.as_bytes())
        .chain_update(policy_digest.as_bytes())
        .chain_update(budget.reservation_digest.as_bytes())
        .finalize();
    let plan = PlanRevisionRef {
        plan_id,
        taskrun_id: taskrun,
        cycle_id: cycle,
        revision: 1,
        context_manifest_ref: context.clone(),
        expected_proposal_indexes: vec![0, 1],
        proposal_batch_digest: batch_digest,
        planning_policy_ref: ResultRef::new(
            ResultId::from_bytes(stable_id(policy_digest.as_bytes(), b"policy")),
            "application/vnd.runne.d2-policy.v1+json",
            policy_digest,
        )
        .expect("fixed media type is valid"),
        planning_budget_ref: budget,
        parent_ref: None,
        integrity_digest: digest(plan_hash.into()),
    };
    (context, plan)
}

pub(super) fn digest(bytes: [u8; 32]) -> IntegrityDigest {
    IntegrityDigest::from_bytes(bytes)
}

pub(super) fn stable_id(seed: &[u8], label: &[u8]) -> [u8; 16] {
    let mut bytes: [u8; 16] = Sha256::new()
        .chain_update(b"RUNNE_D2_DETERMINISTIC_ID_V1\0")
        .chain_update(label)
        .chain_update(seed)
        .finalize()[..16]
        .try_into()
        .expect("fixed digest prefix");
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

#[allow(dead_code)]
fn budget_id(bytes: [u8; 16]) -> BudgetReservationId {
    BudgetReservationId::from_bytes(bytes)
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "tool_loop_plan/worker.rs"]
pub(crate) mod worker;

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "tool_loop_plan/coding.rs"]
mod coding;

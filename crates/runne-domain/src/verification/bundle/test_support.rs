use super::*;
use crate::id::{IntegrityDigest, PlanId, ResultId, TaskRunId};
use crate::reference::ResultRef;
use crate::verification::digest::VerificationDigest;
use crate::verification::{PlanEvaluationRef, PlanEvaluationResult};
use uuid::Uuid;

pub fn bytes(n: u8) -> [u8; 16] {
    let mut b = [0; 16];
    b[6] = 0x70;
    b[8] = 0x80;
    b[15] = n;
    b
}
pub fn uid(n: u8) -> Uuid {
    Uuid::from_bytes(bytes(n))
}
pub fn result(n: u8) -> ResultRef {
    ResultRef::new(
        ResultId::from_bytes(bytes(n)),
        "application/json",
        IntegrityDigest::from_bytes([n; 32]),
    )
    .unwrap()
}
pub fn snapshot() -> DeclaredSnapshot {
    DeclaredSnapshot {
        taskrun_id: TaskRunId::from_bytes(bytes(1)),
        task_revision: 1,
        plan_id: PlanId::from_bytes(bytes(2)),
        plan_revision: 2,
        stream_head: 3,
        source_snapshot_digest: IntegrityDigest::from_bytes([4; 32]),
        environment: RevisionRef {
            revision: 1,
            result: result(5),
        },
        required_artifacts: vec![ArtifactBinding {
            slot: 1,
            artifact: RevisionRef {
                revision: 1,
                result: result(6),
            },
        }],
    }
}
pub fn complete() -> BundleMetadata {
    let s = snapshot();
    BundleMetadata {
        schema_version: 1,
        export_id: uid(7),
        revision: 1,
        producer_version: "synthetic-1".into(),
        taskrun_id: s.taskrun_id,
        checked_snapshot: Some(s.clone()),
        plan_evaluation: Some(PlanEvaluationRef {
            evaluation_id: crate::id::PlanEvaluationId::from_bytes(bytes(8)),
            taskrun_id: s.taskrun_id,
            plan_id: s.plan_id,
            plan_revision: 2,
            evaluated_stream_head: 3,
            result: PlanEvaluationResult::Passed,
            gate_definitions_digest: IntegrityDigest::from_bytes([1; 32]),
            evidence_set_digest: IntegrityDigest::from_bytes([2; 32]),
            evaluation_digest: IntegrityDigest::from_bytes([3; 32]),
        }),
        checks: vec![ReportedCheck {
            slot: 1,
            binding: Some(s),
            verifier: Some(DeclaredVerifier {
                id: "self-reported".into(),
                version: "1".into(),
            }),
            declared_acceptance: Some(result(9)),
            result: Some(result(10)),
            evidence: vec![EvidenceMetadataRef {
                evidence_ref_id: uid(11),
                run_id: uid(12),
                profile_id: uid(13),
                profile_digest: VerificationDigest::from_bytes([14; 32]),
                evidence_digest: VerificationDigest::from_bytes([15; 32]),
            }],
            outcome: ReportedCheckOutcome::Passed,
        }],
        provider_finish: ProviderFinish::Finished,
        tool_returns: vec![],
        effects: vec![],
        reviewer: ReviewerDisposition::Accepted,
        manual_override: true,
        cost: ReportedCost {
            model_compute: CostAmount::Unknown(CostUnknownReason::NotCollected),
            human_review: CostAmount::Unknown(CostUnknownReason::Unavailable),
            recovery: CostAmount::KnownUsdMicros(0),
        },
    }
}
pub fn error(b: &BundleMetadata, code: BundleErrorCode, ordinal: usize) {
    assert_eq!(validate_structure(b), Err(BundleError { code, ordinal }));
}

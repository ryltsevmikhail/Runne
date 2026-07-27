use crate::verification::identity::*;
use crate::verification::digest::VerificationDigest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentState { Reserved, Dispatching, Completed, Failed, Invalidated, Abandoned }

#[derive(Clone, Debug)]
pub struct ConsumptionIntent {
    pub intent_id: IntentID,
    pub idempotency_key: IdempotencyKey,
    pub state: IntentState,
    pub gate_head_snapshot_digest: VerificationDigest,
    pub target_artifact_digest: VerificationDigest,
    pub integrity_digest: VerificationDigest,
}

#[derive(Clone, Debug)]
pub enum DispatchEvidence {
    NotStarted,
    Acknowledged { ack_ref: String, outcome: String },
    Unknown,
}

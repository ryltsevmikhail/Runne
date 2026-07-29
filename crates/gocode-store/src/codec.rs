//! Durable codec — encodes and decodes domain types for SQLite BLOB storage.
//!
//! Each codec implements [`StoreCodec`] with a versioned encoding format.
//! Decoding must reject: unknown tags, trailing bytes, oversized values,
//! and unsupported codec versions.

use core::fmt;

use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{
    AggregateScope, ConversationReceipt, IdempotencyScope, OperationTag,
};
use gocode_domain::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
    WakeCondition, WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::context::ContextManifestRef;
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::id::{
    AttemptId, BudgetReservationId, CheckpointId, ContextManifestId, ConversationId, CycleId,
    EffectId, IntegrityDigest, PlanEvaluationId, PlanId, ReconciliationRunId, ResultId, StepId,
    TaskRunId, WakeEvidenceId, WorkspaceId,
};
use gocode_domain::plan::{PlanParentRef, PlanRevisionRef};
use gocode_domain::recovery::{ReconciliationResultRef, ReconciliationStatus};
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use gocode_domain::task_run::{TaskRunEvent, TaskRunState};
use gocode_domain::verification::{PlanEvaluationRef, PlanEvaluationResult};

/// Error from a codec encode/decode operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCodecError {
    /// Unsupported codec version.
    UnsupportedVersion {
        /// The version found in the encoded bytes.
        found: u16,
        /// The version this codec supports.
        supported: u16,
    },
    /// Unknown event tag in the encoded bytes.
    UnknownTag {
        /// The tag byte that was not recognized.
        tag: u8,
        /// Context for debugging (e.g., "TaskRunEvent").
        context: &'static str,
    },
    /// Not enough bytes to decode the value.
    Truncated,
    /// Extra bytes remaining after decoding.
    TrailingBytes {
        /// The number of extra bytes remaining.
        remaining: usize,
    },
    /// A value exceeds its maximum allowed size.
    Oversized {
        /// What was oversized.
        field: &'static str,
        /// The maximum allowed size.
        max: usize,
        /// The actual size.
        actual: usize,
    },
}

impl fmt::Display for StoreCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "unsupported codec version: found {}, supported {}",
                    found, supported
                )
            }
            Self::UnknownTag { tag, context } => {
                write!(f, "unknown tag 0x{:02x} in {}", tag, context)
            }
            Self::Truncated => write!(f, "truncated bytes"),
            Self::TrailingBytes { remaining } => {
                write!(f, "trailing bytes after decode: {}", remaining)
            }
            Self::Oversized { field, max, actual } => {
                write!(
                    f,
                    "{} exceeds max size: max={}, actual={}",
                    field, max, actual
                )
            }
        }
    }
}

impl std::error::Error for StoreCodecError {}

/// Trait for durable encoding/decoding of a type to/from BLOB bytes.
pub trait StoreCodec<T: Sized> {
    /// The codec version (incremented when encoding changes).
    const CODEC_VERSION: u16;

    /// Encode a value to bytes.
    fn encode(&self, value: &T) -> Result<Vec<u8>, StoreCodecError>;

    /// Decode bytes back into a value.
    fn decode(&self, bytes: &[u8]) -> Result<T, StoreCodecError>;
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Write a u16 in big-endian to a Vec.
fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write a u64 in big-endian to a Vec.
fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Write an i64 in big-endian to a Vec.
fn write_i64_be(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Write a length-prefixed byte slice (u16 BE length).
fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    write_u16_be(buf, len);
    buf.extend_from_slice(data);
}

/// Write raw UUID bytes (16 bytes).
fn write_uuid(buf: &mut Vec<u8>, bytes: &[u8; 16]) {
    buf.extend_from_slice(bytes);
}

/// Read a u16 BE from bytes at `pos`, advancing `pos`.
fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, StoreCodecError> {
    if *pos + 2 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

/// Read a u64 BE from bytes at `pos`, advancing `pos`.
fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, StoreCodecError> {
    if *pos + 8 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let v = u64::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

/// Read an i64 BE from bytes at `pos`, advancing `pos`.
fn read_i64_be(bytes: &[u8], pos: &mut usize) -> Result<i64, StoreCodecError> {
    if *pos + 8 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let value = i64::from_be_bytes(
        bytes[*pos..*pos + 8]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 8;
    Ok(value)
}

/// Read 16 bytes as a UUID from `pos`, advancing `pos`.
fn read_uuid(bytes: &[u8], pos: &mut usize) -> Result<[u8; 16], StoreCodecError> {
    if *pos + 16 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[*pos..*pos + 16]);
    *pos += 16;
    Ok(out)
}

/// Read a length-prefixed byte slice (u16 BE length), advancing `pos`.
fn read_len_prefixed<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], StoreCodecError> {
    let len = read_u16_be(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let data = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(data)
}

fn write_digest(buf: &mut Vec<u8>, digest: &IntegrityDigest) {
    buf.extend_from_slice(digest.as_bytes());
}

fn read_digest(bytes: &[u8], pos: &mut usize) -> Result<IntegrityDigest, StoreCodecError> {
    if *pos + 32 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[*pos..*pos + 32]);
    *pos += 32;
    Ok(IntegrityDigest::from_bytes(digest))
}

fn write_string(buf: &mut Vec<u8>, value: &str) -> Result<(), StoreCodecError> {
    if value.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "string",
            max: u16::MAX as usize,
            actual: value.len(),
        });
    }
    write_len_prefixed(buf, value.as_bytes());
    Ok(())
}

fn read_string(
    bytes: &[u8],
    pos: &mut usize,
    context: &'static str,
) -> Result<String, StoreCodecError> {
    String::from_utf8(read_len_prefixed(bytes, pos)?.to_vec())
        .map_err(|_| StoreCodecError::UnknownTag { tag: 0, context })
}

fn write_u32_vec(buf: &mut Vec<u8>, values: &[u32]) -> Result<(), StoreCodecError> {
    if values.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "u32 vector",
            max: u16::MAX as usize,
            actual: values.len(),
        });
    }
    write_u16_be(buf, values.len() as u16);
    for value in values {
        buf.extend_from_slice(&value.to_be_bytes());
    }
    Ok(())
}

fn read_u32_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<u32>, StoreCodecError> {
    let len = read_u16_be(bytes, pos)? as usize;
    let byte_len = len.checked_mul(4).ok_or(StoreCodecError::Oversized {
        field: "u32 vector",
        max: u16::MAX as usize,
        actual: len,
    })?;
    if *pos + byte_len > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let value = u32::from_be_bytes(
            bytes[*pos..*pos + 4]
                .try_into()
                .map_err(|_| StoreCodecError::Truncated)?,
        );
        *pos += 4;
        values.push(value);
    }
    Ok(values)
}

// ── TaskRunEvent codec ───────────────────────────────────────────────────

/// Event tag constants for TaskRunEvent encoding.
const TAG_TASK_RUN_CREATED: u8 = 0x01;
const TAG_TASK_RUN_QUEUED: u8 = 0x02;
const TAG_TASK_RUN_ADMITTED: u8 = 0x03;
const TAG_ATTEMPT_STARTED: u8 = 0x04;
const TAG_WAIT_STARTED: u8 = 0x05;
const TAG_RESUMED: u8 = 0x06;
const TAG_RETRY_STARTED: u8 = 0x07;
const TAG_RETRY_COMPLETED: u8 = 0x08;
const TAG_CHECKPOINT_STARTED: u8 = 0x09;
const TAG_CHECKPOINT_COMMITTED: u8 = 0x0A;
const TAG_CANCELLATION_REQUESTED: u8 = 0x0B;
const TAG_CANCELLATION_COMPLETED: u8 = 0x0C;
const TAG_TASK_RUN_COMPLETED: u8 = 0x0D;
const TAG_TASK_RUN_FAILED: u8 = 0x0E;
const TAG_BUDGET_EXHAUSTED: u8 = 0x0F;
const TAG_POLICY_DENIED: u8 = 0x10;
const TAG_RECONCILIATION_STARTED: u8 = 0x11;
const TAG_RECONCILED: u8 = 0x12;
const TAG_UNRECOVERABLE: u8 = 0x13;
const TAG_TASK_RUN_CANCELLED: u8 = 0x14;
const TAG_LOOP_CYCLE_STARTED: u8 = 0x15;
const TAG_CONTEXT_COMMITTED: u8 = 0x16;
const TAG_PLAN_COMMITTED: u8 = 0x17;
const TAG_STEP_OUTCOME_RECORDED: u8 = 0x18;
const TAG_LOOP_CYCLE_COMPLETED: u8 = 0x19;
const TAG_NEXT_CYCLE_CREATED: u8 = 0x1A;
const TAG_RETRY_SCHEDULED: u8 = 0x1B;
const TAG_LOOP_CHECKPOINT_RECORDED: u8 = 0x1C;
const TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT: u8 = 0x1D;
const TAG_RECOVERY_RESUME_STARTED: u8 = 0x1E;
const TAG_LOOP_CHECKPOINT_STARTED: u8 = 0x1F;
const TAG_LOOP_CHECKPOINT_COMMITTED: u8 = 0x20;
const TAG_LOOP_WAKE_ACCEPTED: u8 = 0x21;

fn encode_context_ref(
    buf: &mut Vec<u8>,
    value: &ContextManifestRef,
) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.manifest_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    write_uuid(buf, value.cycle_id.as_bytes());
    write_u64_be(buf, value.revision);
    write_string(buf, &value.policy_revision)?;
    write_digest(buf, &value.integrity_digest);
    Ok(())
}

fn decode_context_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ContextManifestRef, StoreCodecError> {
    Ok(ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(read_uuid(bytes, pos)?),
        taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, pos)?),
        attempt_id: AttemptId::from_bytes(read_uuid(bytes, pos)?),
        cycle_id: CycleId::from_bytes(read_uuid(bytes, pos)?),
        revision: read_u64_be(bytes, pos)?,
        policy_revision: read_string(bytes, pos, "ContextManifestRef policy revision")?,
        integrity_digest: read_digest(bytes, pos)?,
    })
}

fn encode_result_ref(buf: &mut Vec<u8>, value: &ResultRef) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.result_id.as_bytes());
    write_string(buf, &value.media_type)?;
    write_digest(buf, &value.integrity_digest);
    Ok(())
}

fn decode_result_ref(bytes: &[u8], pos: &mut usize) -> Result<ResultRef, StoreCodecError> {
    ResultRef::new(
        ResultId::from_bytes(read_uuid(bytes, pos)?),
        read_string(bytes, pos, "ResultRef media type")?,
        read_digest(bytes, pos)?,
    )
    .map_err(|_| StoreCodecError::UnknownTag {
        tag: 0,
        context: "ResultRef",
    })
}

fn encode_budget_ref(buf: &mut Vec<u8>, value: &BudgetReservationRef) {
    write_uuid(buf, value.reservation_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    write_u64_be(buf, value.retry_ordinal);
    write_digest(buf, &value.reservation_digest);
}

fn decode_budget_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<BudgetReservationRef, StoreCodecError> {
    Ok(BudgetReservationRef {
        reservation_id: BudgetReservationId::from_bytes(read_uuid(bytes, pos)?),
        taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, pos)?),
        attempt_id: AttemptId::from_bytes(read_uuid(bytes, pos)?),
        retry_ordinal: read_u64_be(bytes, pos)?,
        reservation_digest: read_digest(bytes, pos)?,
    })
}

fn encode_plan_ref(buf: &mut Vec<u8>, value: &PlanRevisionRef) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.plan_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.cycle_id.as_bytes());
    write_u64_be(buf, value.revision);
    encode_context_ref(buf, &value.context_manifest_ref)?;
    write_u32_vec(buf, &value.expected_proposal_indexes)?;
    write_digest(buf, &value.proposal_batch_digest);
    encode_result_ref(buf, &value.planning_policy_ref)?;
    encode_budget_ref(buf, &value.planning_budget_ref);
    match &value.parent_ref {
        None => buf.push(0),
        Some(parent) => {
            buf.push(1);
            write_uuid(buf, parent.plan_id.as_bytes());
            write_u64_be(buf, parent.revision);
            write_digest(buf, &parent.integrity_digest);
        }
    }
    write_digest(buf, &value.integrity_digest);
    Ok(())
}

fn decode_plan_ref(bytes: &[u8], pos: &mut usize) -> Result<PlanRevisionRef, StoreCodecError> {
    let plan_id = PlanId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let revision = read_u64_be(bytes, pos)?;
    let context_manifest_ref = decode_context_ref(bytes, pos)?;
    let expected_proposal_indexes = read_u32_vec(bytes, pos)?;
    if expected_proposal_indexes
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(StoreCodecError::UnknownTag {
            tag: 0,
            context: "PlanRevisionRef proposal indexes",
        });
    }
    let proposal_batch_digest = read_digest(bytes, pos)?;
    let planning_policy_ref = decode_result_ref(bytes, pos)?;
    let planning_budget_ref = decode_budget_ref(bytes, pos)?;
    let parent_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(PlanParentRef {
                plan_id: PlanId::from_bytes(read_uuid(bytes, pos)?),
                revision: read_u64_be(bytes, pos)?,
                integrity_digest: read_digest(bytes, pos)?,
            })
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "PlanRevisionRef parent",
            });
        }
    };
    Ok(PlanRevisionRef {
        plan_id,
        taskrun_id,
        cycle_id,
        revision,
        context_manifest_ref,
        expected_proposal_indexes,
        proposal_batch_digest,
        planning_policy_ref,
        planning_budget_ref,
        parent_ref,
        integrity_digest: read_digest(bytes, pos)?,
    })
}

fn encode_step_ref(buf: &mut Vec<u8>, value: &StepOutcomeRef) {
    write_uuid(buf, value.cycle_id.as_bytes());
    buf.extend_from_slice(&value.proposal_index.to_be_bytes());
    write_uuid(buf, value.step_id.as_bytes());
    write_digest(buf, &value.outcome_digest);
}

fn decode_step_ref(bytes: &[u8], pos: &mut usize) -> Result<StepOutcomeRef, StoreCodecError> {
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    if *pos + 4 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let proposal_index = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 4;
    Ok(StepOutcomeRef {
        cycle_id,
        proposal_index,
        step_id: StepId::from_bytes(read_uuid(bytes, pos)?),
        outcome_digest: read_digest(bytes, pos)?,
    })
}

fn encode_step_record(buf: &mut Vec<u8>, value: &StepOutcomeRecord) -> Result<(), StoreCodecError> {
    buf.extend_from_slice(&value.proposal_index.to_be_bytes());
    write_uuid(buf, value.step_id.as_bytes());
    buf.push(match value.outcome_type {
        StepOutcomeType::Succeeded => 0,
        StepOutcomeType::FailedBeforeCommit => 1,
        StepOutcomeType::FailedAfterCommit => 2,
        StepOutcomeType::Uncertain => 3,
        StepOutcomeType::Cancelled => 4,
    });
    match &value.result_ref {
        None => buf.push(0),
        Some(result) => {
            buf.push(1);
            encode_result_ref(buf, result)?;
        }
    }
    match value.effect_id {
        None => buf.push(0),
        Some(effect_id) => {
            buf.push(1);
            write_uuid(buf, effect_id.as_bytes());
        }
    }
    if value.evidence_digests.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "StepOutcomeRecord evidence",
            max: u16::MAX as usize,
            actual: value.evidence_digests.len(),
        });
    }
    write_u16_be(buf, value.evidence_digests.len() as u16);
    for digest in &value.evidence_digests {
        write_digest(buf, digest);
    }
    Ok(())
}

fn decode_step_record(bytes: &[u8], pos: &mut usize) -> Result<StepOutcomeRecord, StoreCodecError> {
    if *pos + 4 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let proposal_index = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 4;
    let step_id = StepId::from_bytes(read_uuid(bytes, pos)?);
    let outcome_tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let outcome_type = match outcome_tag {
        0 => StepOutcomeType::Succeeded,
        1 => StepOutcomeType::FailedBeforeCommit,
        2 => StepOutcomeType::FailedAfterCommit,
        3 => StepOutcomeType::Uncertain,
        4 => StepOutcomeType::Cancelled,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeType",
            });
        }
    };
    let result_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_result_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeRecord result option",
            });
        }
    };
    let effect_id = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(EffectId::from_bytes(read_uuid(bytes, pos)?))
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeRecord effect option",
            });
        }
    };
    let evidence_len = read_u16_be(bytes, pos)? as usize;
    let mut evidence_digests = Vec::with_capacity(evidence_len);
    for _ in 0..evidence_len {
        evidence_digests.push(read_digest(bytes, pos)?);
    }
    Ok(StepOutcomeRecord {
        proposal_index,
        step_id,
        outcome_type,
        result_ref,
        effect_id,
        evidence_digests,
    })
}

fn encode_wake_condition(buf: &mut Vec<u8>, value: &WakeCondition) -> Result<(), StoreCodecError> {
    buf.push(match value.kind {
        WakeConditionKind::ExternalInput => 0,
        WakeConditionKind::Approval => 1,
        WakeConditionKind::ChildTaskRun => 2,
        WakeConditionKind::Timer => 3,
        WakeConditionKind::Reconciliation => 4,
    });
    write_string(buf, &value.condition_ref)?;
    write_digest(buf, &value.condition_digest);
    Ok(())
}

fn decode_wake_condition(bytes: &[u8], pos: &mut usize) -> Result<WakeCondition, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let kind = match tag {
        0 => WakeConditionKind::ExternalInput,
        1 => WakeConditionKind::Approval,
        2 => WakeConditionKind::ChildTaskRun,
        3 => WakeConditionKind::Timer,
        4 => WakeConditionKind::Reconciliation,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "WakeConditionKind",
            });
        }
    };
    Ok(WakeCondition {
        kind,
        condition_ref: read_string(bytes, pos, "WakeCondition reference")?,
        condition_digest: read_digest(bytes, pos)?,
    })
}

fn encode_wake_evidence(buf: &mut Vec<u8>, value: &WakeEvidenceRef) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.cycle_id.as_bytes());
    write_digest(buf, &value.condition_digest);
    buf.push(match value.source {
        WakeEvidenceSource::ExternalInput => 0,
        WakeEvidenceSource::Approval => 1,
        WakeEvidenceSource::ChildTaskRun => 2,
        WakeEvidenceSource::Timer => 3,
        WakeEvidenceSource::Reconciliation => 4,
    });
    write_uuid(buf, value.evidence_id.as_bytes());
    write_digest(buf, &value.evidence_digest);
    write_i64_be(buf, value.observed_at_unix_us);
    write_string(buf, &value.authority_revision)
}

fn decode_wake_evidence(bytes: &[u8], pos: &mut usize) -> Result<WakeEvidenceRef, StoreCodecError> {
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let condition_digest = read_digest(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let source = match tag {
        0 => WakeEvidenceSource::ExternalInput,
        1 => WakeEvidenceSource::Approval,
        2 => WakeEvidenceSource::ChildTaskRun,
        3 => WakeEvidenceSource::Timer,
        4 => WakeEvidenceSource::Reconciliation,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "WakeEvidenceSource",
            });
        }
    };
    Ok(WakeEvidenceRef {
        cycle_id,
        condition_digest,
        source,
        evidence_id: WakeEvidenceId::from_bytes(read_uuid(bytes, pos)?),
        evidence_digest: read_digest(bytes, pos)?,
        observed_at_unix_us: read_i64_be(bytes, pos)?,
        authority_revision: read_string(bytes, pos, "WakeEvidence authority revision")?,
    })
}

fn encode_plan_evaluation(buf: &mut Vec<u8>, value: &PlanEvaluationRef) {
    write_uuid(buf, value.evaluation_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.plan_id.as_bytes());
    write_u64_be(buf, value.plan_revision);
    write_u64_be(buf, value.evaluated_stream_head);
    buf.push(match value.result {
        PlanEvaluationResult::Passed => 0,
        PlanEvaluationResult::Failed => 1,
        PlanEvaluationResult::Blocked => 2,
        PlanEvaluationResult::RequiresReview => 3,
    });
    write_digest(buf, &value.gate_definitions_digest);
    write_digest(buf, &value.evidence_set_digest);
    write_digest(buf, &value.evaluation_digest);
}

fn decode_plan_evaluation(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<PlanEvaluationRef, StoreCodecError> {
    let evaluation_id = PlanEvaluationId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let plan_id = PlanId::from_bytes(read_uuid(bytes, pos)?);
    let plan_revision = read_u64_be(bytes, pos)?;
    let evaluated_stream_head = read_u64_be(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let result = match tag {
        0 => PlanEvaluationResult::Passed,
        1 => PlanEvaluationResult::Failed,
        2 => PlanEvaluationResult::Blocked,
        3 => PlanEvaluationResult::RequiresReview,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "PlanEvaluationResult",
            });
        }
    };
    Ok(PlanEvaluationRef {
        evaluation_id,
        taskrun_id,
        plan_id,
        plan_revision,
        evaluated_stream_head,
        result,
        gate_definitions_digest: read_digest(bytes, pos)?,
        evidence_set_digest: read_digest(bytes, pos)?,
        evaluation_digest: read_digest(bytes, pos)?,
    })
}

fn encode_disposition(buf: &mut Vec<u8>, value: &LoopDisposition) -> Result<(), StoreCodecError> {
    match value {
        LoopDisposition::Continue => buf.push(0),
        LoopDisposition::Wait {
            reason,
            wake_condition,
        } => {
            buf.push(1);
            write_string(buf, reason)?;
            encode_wake_condition(buf, wake_condition)?;
        }
        LoopDisposition::Complete {
            plan_evaluation_ref,
        } => {
            buf.push(2);
            encode_plan_evaluation(buf, plan_evaluation_ref);
        }
        LoopDisposition::Fail {
            reason,
            unresolved_proposals,
        } => {
            buf.push(3);
            write_string(buf, reason)?;
            write_u32_vec(buf, unresolved_proposals)?;
        }
    }
    Ok(())
}

fn decode_disposition(bytes: &[u8], pos: &mut usize) -> Result<LoopDisposition, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    match tag {
        0 => Ok(LoopDisposition::Continue),
        1 => Ok(LoopDisposition::Wait {
            reason: read_string(bytes, pos, "LoopDisposition wait reason")?,
            wake_condition: decode_wake_condition(bytes, pos)?,
        }),
        2 => Ok(LoopDisposition::Complete {
            plan_evaluation_ref: decode_plan_evaluation(bytes, pos)?,
        }),
        3 => Ok(LoopDisposition::Fail {
            reason: read_string(bytes, pos, "LoopDisposition fail reason")?,
            unresolved_proposals: read_u32_vec(bytes, pos)?,
        }),
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "LoopDisposition",
        }),
    }
}

fn encode_checkpoint_ref(buf: &mut Vec<u8>, value: &CheckpointRef) {
    write_uuid(buf, value.checkpoint_id.as_bytes());
    write_u64_be(buf, value.event_position);
    write_digest(buf, &value.integrity_digest);
}

fn decode_checkpoint_ref(bytes: &[u8], pos: &mut usize) -> Result<CheckpointRef, StoreCodecError> {
    Ok(CheckpointRef {
        checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, pos)?),
        event_position: read_u64_be(bytes, pos)?,
        integrity_digest: read_digest(bytes, pos)?,
    })
}

fn encode_reconciliation_ref(buf: &mut Vec<u8>, value: &ReconciliationResultRef) {
    write_uuid(buf, value.reconciliation_run_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.predecessor_attempt_id.as_bytes());
    write_u64_be(buf, value.recovery_generation);
    write_u64_be(buf, value.reconciled_stream_position);
    buf.push(match value.status {
        ReconciliationStatus::Reconciled => 0,
        ReconciliationStatus::Failed => 1,
        ReconciliationStatus::InProgress => 2,
    });
    write_u64_be(buf, value.unresolved_effect_count);
    write_digest(buf, &value.result_digest);
}

fn decode_reconciliation_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ReconciliationResultRef, StoreCodecError> {
    let reconciliation_run_id = ReconciliationRunId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let predecessor_attempt_id = AttemptId::from_bytes(read_uuid(bytes, pos)?);
    let recovery_generation = read_u64_be(bytes, pos)?;
    let reconciled_stream_position = read_u64_be(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let status = match tag {
        0 => ReconciliationStatus::Reconciled,
        1 => ReconciliationStatus::Failed,
        2 => ReconciliationStatus::InProgress,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "ReconciliationStatus",
            });
        }
    };
    Ok(ReconciliationResultRef {
        reconciliation_run_id,
        taskrun_id,
        predecessor_attempt_id,
        recovery_generation,
        reconciled_stream_position,
        status,
        unresolved_effect_count: read_u64_be(bytes, pos)?,
        result_digest: read_digest(bytes, pos)?,
    })
}

fn encode_checkpoint_body(
    buf: &mut Vec<u8>,
    value: &LoopCheckpointBody,
) -> Result<(), StoreCodecError> {
    write_string(buf, &value.schema_version)?;
    write_uuid(buf, value.cycle_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    match &value.plan_revision_ref {
        None => buf.push(0),
        Some(plan_ref) => {
            buf.push(1);
            encode_plan_ref(buf, plan_ref)?;
        }
    }
    match &value.context_manifest_ref {
        None => buf.push(0),
        Some(context_ref) => {
            buf.push(1);
            encode_context_ref(buf, context_ref)?;
        }
    }
    if value.step_outcome_refs.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "LoopCheckpointBody step outcomes",
            max: u16::MAX as usize,
            actual: value.step_outcome_refs.len(),
        });
    }
    write_u16_be(buf, value.step_outcome_refs.len() as u16);
    for step_ref in &value.step_outcome_refs {
        encode_step_ref(buf, step_ref);
    }
    Ok(())
}

fn decode_checkpoint_body(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<LoopCheckpointBody, StoreCodecError> {
    let schema_version = read_string(bytes, pos, "LoopCheckpointBody schema version")?;
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let attempt_id = AttemptId::from_bytes(read_uuid(bytes, pos)?);
    let plan_revision_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_plan_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "LoopCheckpointBody plan option",
            });
        }
    };
    let context_manifest_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_context_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "LoopCheckpointBody context option",
            });
        }
    };
    let len = read_u16_be(bytes, pos)? as usize;
    let mut step_outcome_refs = Vec::with_capacity(len);
    for _ in 0..len {
        step_outcome_refs.push(decode_step_ref(bytes, pos)?);
    }
    Ok(LoopCheckpointBody {
        schema_version,
        cycle_id,
        attempt_id,
        plan_revision_ref,
        context_manifest_ref,
        step_outcome_refs,
    })
}

/// Codec for [`TaskRunEvent`] payload BLOB.
pub struct TaskRunEventCodec;

impl StoreCodec<TaskRunEvent> for TaskRunEventCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &TaskRunEvent) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        match value {
            TaskRunEvent::TaskRunCreated => {
                buf.push(TAG_TASK_RUN_CREATED);
            }
            TaskRunEvent::TaskRunQueued => {
                buf.push(TAG_TASK_RUN_QUEUED);
            }
            TaskRunEvent::TaskRunAdmitted => {
                buf.push(TAG_TASK_RUN_ADMITTED);
            }
            TaskRunEvent::AttemptStarted { attempt_id } => {
                buf.push(TAG_ATTEMPT_STARTED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::WaitStarted => {
                buf.push(TAG_WAIT_STARTED);
            }
            TaskRunEvent::Resumed => {
                buf.push(TAG_RESUMED);
            }
            TaskRunEvent::RetryStarted { attempt_id } => {
                buf.push(TAG_RETRY_STARTED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::RetryCompleted { attempt_id } => {
                buf.push(TAG_RETRY_COMPLETED);
                write_uuid(&mut buf, attempt_id.as_bytes());
            }
            TaskRunEvent::CheckpointStarted => {
                buf.push(TAG_CHECKPOINT_STARTED);
            }
            TaskRunEvent::CheckpointCommitted => {
                buf.push(TAG_CHECKPOINT_COMMITTED);
            }
            TaskRunEvent::CancellationRequested => {
                buf.push(TAG_CANCELLATION_REQUESTED);
            }
            TaskRunEvent::CancellationCompleted => {
                buf.push(TAG_CANCELLATION_COMPLETED);
            }
            TaskRunEvent::TaskRunCompleted { result } => {
                buf.push(TAG_TASK_RUN_COMPLETED);
                encode_terminal_result(&mut buf, result);
            }
            TaskRunEvent::TaskRunFailed { reason } => {
                buf.push(TAG_TASK_RUN_FAILED);
                write_len_prefixed(&mut buf, reason.as_bytes());
            }
            TaskRunEvent::BudgetExhausted => {
                buf.push(TAG_BUDGET_EXHAUSTED);
            }
            TaskRunEvent::PolicyDenied => {
                buf.push(TAG_POLICY_DENIED);
            }
            TaskRunEvent::ReconciliationStarted => {
                buf.push(TAG_RECONCILIATION_STARTED);
            }
            TaskRunEvent::Reconciled => {
                buf.push(TAG_RECONCILED);
            }
            TaskRunEvent::Unrecoverable => {
                buf.push(TAG_UNRECOVERABLE);
            }
            TaskRunEvent::TaskRunCancelled => {
                buf.push(TAG_TASK_RUN_CANCELLED);
            }
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence,
                parent_cycle_id,
            } => {
                buf.push(TAG_LOOP_CYCLE_STARTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *sequence);
                match parent_cycle_id {
                    None => buf.push(0),
                    Some(parent) => {
                        buf.push(1);
                        write_uuid(&mut buf, parent.as_bytes());
                    }
                }
            }
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref,
            } => {
                buf.push(TAG_CONTEXT_COMMITTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_context_ref(&mut buf, manifest_ref)?;
            }
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref,
                input_digest,
                output_digest,
                expected_proposal_indexes,
            } => {
                buf.push(TAG_PLAN_COMMITTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_plan_ref(&mut buf, plan_revision_ref)?;
                write_digest(&mut buf, input_digest);
                write_digest(&mut buf, output_digest);
                write_u32_vec(&mut buf, expected_proposal_indexes)?;
            }
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => {
                buf.push(TAG_STEP_OUTCOME_RECORDED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_step_record(&mut buf, outcome)?;
            }
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition,
            } => {
                buf.push(TAG_LOOP_CYCLE_COMPLETED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                encode_disposition(&mut buf, disposition)?;
            }
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id,
                successor_cycle_id,
                attempt_id,
                sequence,
            } => {
                buf.push(TAG_NEXT_CYCLE_CREATED);
                write_uuid(&mut buf, parent_cycle_id.as_bytes());
                write_uuid(&mut buf, successor_cycle_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *sequence);
            }
            TaskRunEvent::RetryScheduled {
                ordinal,
                old_attempt_id,
                new_attempt_id,
                abandoned_cycle_id,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                buf.push(TAG_RETRY_SCHEDULED);
                write_u64_be(&mut buf, *ordinal);
                write_uuid(&mut buf, old_attempt_id.as_bytes());
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_uuid(&mut buf, abandoned_cycle_id.as_bytes());
                encode_step_ref(&mut buf, step_outcome_ref);
                write_digest(&mut buf, retry_policy_digest);
                encode_budget_ref(&mut buf, budget_reservation_ref);
                write_u64_be(&mut buf, *delay_ms);
                write_i64_be(&mut buf, *due_at_unix_us);
            }
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal,
                attempt_id,
                activated_at_unix_us,
            } => {
                buf.push(TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT);
                write_u64_be(&mut buf, *ordinal);
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_i64_be(&mut buf, *activated_at_unix_us);
            }
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id,
                new_generation,
                abandoned_cycle_id,
                context_manifest_ref,
                checkpoint_ref,
                reconciliation_ref,
            } => {
                buf.push(TAG_RECOVERY_RESUME_STARTED);
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_generation);
                match abandoned_cycle_id {
                    None => buf.push(0),
                    Some(cycle_id) => {
                        buf.push(1);
                        write_uuid(&mut buf, cycle_id.as_bytes());
                    }
                }
                encode_context_ref(&mut buf, context_manifest_ref)?;
                encode_checkpoint_ref(&mut buf, checkpoint_ref);
                encode_reconciliation_ref(&mut buf, reconciliation_ref);
            }
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_STARTED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_RECORDED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                encode_checkpoint_body(&mut buf, body)?;
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                buf.push(TAG_LOOP_CHECKPOINT_COMMITTED);
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_digest(&mut buf, integrity_digest);
            }
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref,
            } => {
                buf.push(TAG_LOOP_WAKE_ACCEPTED);
                write_uuid(&mut buf, cycle_id.as_bytes());
                encode_wake_evidence(&mut buf, wake_evidence_ref)?;
            }
        }
        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<TaskRunEvent, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let tag = bytes[pos];
        pos += 1;

        let event = match tag {
            TAG_TASK_RUN_CREATED => TaskRunEvent::TaskRunCreated,
            TAG_TASK_RUN_QUEUED => TaskRunEvent::TaskRunQueued,
            TAG_TASK_RUN_ADMITTED => TaskRunEvent::TaskRunAdmitted,
            TAG_ATTEMPT_STARTED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::AttemptStarted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_WAIT_STARTED => TaskRunEvent::WaitStarted,
            TAG_RESUMED => TaskRunEvent::Resumed,
            TAG_RETRY_STARTED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::RetryStarted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_RETRY_COMPLETED => {
                let aid = read_uuid(bytes, &mut pos)?;
                TaskRunEvent::RetryCompleted {
                    attempt_id: AttemptId::from_bytes(aid),
                }
            }
            TAG_CHECKPOINT_STARTED => TaskRunEvent::CheckpointStarted,
            TAG_CHECKPOINT_COMMITTED => TaskRunEvent::CheckpointCommitted,
            TAG_CANCELLATION_REQUESTED => TaskRunEvent::CancellationRequested,
            TAG_CANCELLATION_COMPLETED => TaskRunEvent::CancellationCompleted,
            TAG_TASK_RUN_COMPLETED => {
                let result = decode_terminal_result(bytes, &mut pos)?;
                TaskRunEvent::TaskRunCompleted { result }
            }
            TAG_TASK_RUN_FAILED => {
                let reason_bytes = read_len_prefixed(bytes, &mut pos)?;
                let reason = String::from_utf8(reason_bytes.to_vec()).map_err(|_| {
                    StoreCodecError::UnknownTag {
                        tag,
                        context: "TaskRunFailed reason (invalid UTF-8)",
                    }
                })?;
                TaskRunEvent::TaskRunFailed { reason }
            }
            TAG_BUDGET_EXHAUSTED => TaskRunEvent::BudgetExhausted,
            TAG_POLICY_DENIED => TaskRunEvent::PolicyDenied,
            TAG_RECONCILIATION_STARTED => TaskRunEvent::ReconciliationStarted,
            TAG_RECONCILED => TaskRunEvent::Reconciled,
            TAG_UNRECOVERABLE => TaskRunEvent::Unrecoverable,
            TAG_TASK_RUN_CANCELLED => TaskRunEvent::TaskRunCancelled,
            TAG_LOOP_CYCLE_STARTED => {
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let sequence = read_u64_be(bytes, &mut pos)?;
                let parent_cycle_id = match *bytes.get(pos).ok_or(StoreCodecError::Truncated)? {
                    0 => {
                        pos += 1;
                        None
                    }
                    1 => {
                        pos += 1;
                        Some(CycleId::from_bytes(read_uuid(bytes, &mut pos)?))
                    }
                    tag => {
                        return Err(StoreCodecError::UnknownTag {
                            tag,
                            context: "LoopCycleStarted parent",
                        });
                    }
                };
                TaskRunEvent::LoopCycleStarted {
                    cycle_id,
                    attempt_id,
                    sequence,
                    parent_cycle_id,
                }
            }
            TAG_CONTEXT_COMMITTED => TaskRunEvent::ContextCommitted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                manifest_ref: decode_context_ref(bytes, &mut pos)?,
            },
            TAG_PLAN_COMMITTED => {
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let plan_revision_ref = decode_plan_ref(bytes, &mut pos)?;
                let input_digest = read_digest(bytes, &mut pos)?;
                let output_digest = read_digest(bytes, &mut pos)?;
                let expected_proposal_indexes = read_u32_vec(bytes, &mut pos)?;
                if expected_proposal_indexes
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                    || expected_proposal_indexes != plan_revision_ref.expected_proposal_indexes
                {
                    return Err(StoreCodecError::UnknownTag {
                        tag,
                        context: "PlanCommitted proposal indexes",
                    });
                }
                TaskRunEvent::PlanCommitted {
                    cycle_id,
                    plan_revision_ref,
                    input_digest,
                    output_digest,
                    expected_proposal_indexes,
                }
            }
            TAG_STEP_OUTCOME_RECORDED => TaskRunEvent::StepOutcomeRecorded {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                outcome: decode_step_record(bytes, &mut pos)?,
            },
            TAG_LOOP_CYCLE_COMPLETED => TaskRunEvent::LoopCycleCompleted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                disposition: decode_disposition(bytes, &mut pos)?,
            },
            TAG_NEXT_CYCLE_CREATED => TaskRunEvent::NextCycleCreated {
                parent_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                successor_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                sequence: read_u64_be(bytes, &mut pos)?,
            },
            TAG_RETRY_SCHEDULED => TaskRunEvent::RetryScheduled {
                ordinal: read_u64_be(bytes, &mut pos)?,
                old_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                abandoned_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                step_outcome_ref: decode_step_ref(bytes, &mut pos)?,
                retry_policy_digest: read_digest(bytes, &mut pos)?,
                budget_reservation_ref: decode_budget_ref(bytes, &mut pos)?,
                delay_ms: read_u64_be(bytes, &mut pos)?,
                due_at_unix_us: read_i64_be(bytes, &mut pos)?,
            },
            TAG_ACTIVATE_SCHEDULED_RETRY_ATTEMPT => TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal: read_u64_be(bytes, &mut pos)?,
                attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                activated_at_unix_us: read_i64_be(bytes, &mut pos)?,
            },
            TAG_RECOVERY_RESUME_STARTED => {
                let new_attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_generation = read_u64_be(bytes, &mut pos)?;
                let abandoned_cycle_id = match *bytes.get(pos).ok_or(StoreCodecError::Truncated)? {
                    0 => {
                        pos += 1;
                        None
                    }
                    1 => {
                        pos += 1;
                        Some(CycleId::from_bytes(read_uuid(bytes, &mut pos)?))
                    }
                    tag => {
                        return Err(StoreCodecError::UnknownTag {
                            tag,
                            context: "RecoveryResumeStarted abandoned cycle",
                        });
                    }
                };
                TaskRunEvent::RecoveryResumeStarted {
                    new_attempt_id,
                    new_generation,
                    abandoned_cycle_id,
                    context_manifest_ref: decode_context_ref(bytes, &mut pos)?,
                    checkpoint_ref: decode_checkpoint_ref(bytes, &mut pos)?,
                    reconciliation_ref: decode_reconciliation_ref(bytes, &mut pos)?,
                }
            }
            TAG_LOOP_CHECKPOINT_STARTED => TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_CHECKPOINT_RECORDED => TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                body: decode_checkpoint_body(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_CHECKPOINT_COMMITTED => TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                integrity_digest: read_digest(bytes, &mut pos)?,
            },
            TAG_LOOP_WAKE_ACCEPTED => TaskRunEvent::LoopWakeAccepted {
                cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                wake_evidence_ref: decode_wake_evidence(bytes, &mut pos)?,
            },
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRunEvent",
                });
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(event)
    }
}

// ── ConversationEvent codec ──────────────────────────────────────────────

const TAG_CONVERSATION_CREATED: u8 = 0x20;
const TAG_CONVERSATION_CLOSED: u8 = 0x21;

/// Codec for [`ConversationEvent`] payload BLOBs.
pub struct ConversationEventCodec;

impl StoreCodec<ConversationEvent> for ConversationEventCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &ConversationEvent) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(19);
        write_u16_be(&mut buffer, Self::CODEC_VERSION);
        match value {
            ConversationEvent::ConversationCreated { workspace_id } => {
                buffer.push(TAG_CONVERSATION_CREATED);
                write_uuid(&mut buffer, workspace_id.as_bytes());
            }
            ConversationEvent::ConversationClosed => buffer.push(TAG_CONVERSATION_CLOSED),
        }
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ConversationEvent, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let tag = *bytes.get(position).ok_or(StoreCodecError::Truncated)?;
        position += 1;
        let event = match tag {
            TAG_CONVERSATION_CREATED => {
                let workspace_bytes = read_uuid(bytes, &mut position)?;
                let workspace_id = WorkspaceId::from_bytes(workspace_bytes);
                workspace_id
                    .to_string()
                    .parse::<WorkspaceId>()
                    .map_err(|_| StoreCodecError::UnknownTag {
                        tag,
                        context: "ConversationCreated workspace UUIDv7",
                    })?;
                ConversationEvent::ConversationCreated { workspace_id }
            }
            TAG_CONVERSATION_CLOSED => ConversationEvent::ConversationClosed,
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "ConversationEvent",
                });
            }
        };
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(event)
    }
}

/// Encode a [`TerminalResult`] into a buffer.
fn encode_terminal_result(buf: &mut Vec<u8>, result: &TerminalResult) {
    match result {
        TerminalResult::Success => {
            buf.push(0x00);
        }
        TerminalResult::Failure { reason } => {
            buf.push(0x01);
            write_len_prefixed(buf, reason.as_bytes());
        }
    }
}

/// Decode a [`TerminalResult`] from bytes at `pos`.
fn decode_terminal_result(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<TerminalResult, StoreCodecError> {
    if *pos >= bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let tag = bytes[*pos];
    *pos += 1;
    match tag {
        0x00 => Ok(TerminalResult::Success),
        0x01 => {
            let reason_bytes = read_len_prefixed(bytes, pos)?;
            let reason = String::from_utf8(reason_bytes.to_vec()).map_err(|_| {
                StoreCodecError::UnknownTag {
                    tag: 0x01,
                    context: "TerminalResult::Failure reason (invalid UTF-8)",
                }
            })?;
            Ok(TerminalResult::Failure { reason })
        }
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "TerminalResult",
        }),
    }
}

fn encode_taskrun_state(state: TaskRunState) -> u8 {
    match state {
        TaskRunState::Created => 0,
        TaskRunState::Queued => 1,
        TaskRunState::Admitted => 2,
        TaskRunState::Running => 3,
        TaskRunState::Waiting => 4,
        TaskRunState::Retrying => 5,
        TaskRunState::Checkpointing => 6,
        TaskRunState::Cancelling => 7,
        TaskRunState::Reconciling => 8,
        TaskRunState::Succeeded => 9,
        TaskRunState::Failed => 10,
        TaskRunState::Cancelled => 11,
        TaskRunState::BudgetExhausted => 12,
        TaskRunState::PolicyDenied => 13,
        TaskRunState::Unrecoverable => 14,
    }
}

fn decode_taskrun_state(bytes: &[u8], pos: &mut usize) -> Result<TaskRunState, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    match tag {
        0 => Ok(TaskRunState::Created),
        1 => Ok(TaskRunState::Queued),
        2 => Ok(TaskRunState::Admitted),
        3 => Ok(TaskRunState::Running),
        4 => Ok(TaskRunState::Waiting),
        5 => Ok(TaskRunState::Retrying),
        6 => Ok(TaskRunState::Checkpointing),
        7 => Ok(TaskRunState::Cancelling),
        8 => Ok(TaskRunState::Reconciling),
        9 => Ok(TaskRunState::Succeeded),
        10 => Ok(TaskRunState::Failed),
        11 => Ok(TaskRunState::Cancelled),
        12 => Ok(TaskRunState::BudgetExhausted),
        13 => Ok(TaskRunState::PolicyDenied),
        14 => Ok(TaskRunState::Unrecoverable),
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "TaskRunState",
        }),
    }
}

// ── CommandOutcome codec ─────────────────────────────────────────────────

const CO_TAG_CREATED: u8 = 0x01;
const CO_TAG_QUEUED: u8 = 0x02;
const CO_TAG_ADMITTED: u8 = 0x03;
const CO_TAG_ATTEMPT_STARTED: u8 = 0x04;
const CO_TAG_COMPLETED: u8 = 0x05;
const CO_TAG_CYCLE_STARTED: u8 = 0x06;
const CO_TAG_CONTEXT_COMMITTED: u8 = 0x07;
const CO_TAG_PLAN_COMMITTED: u8 = 0x08;
const CO_TAG_STEP_OUTCOME_RECORDED: u8 = 0x09;
const CO_TAG_LOOP_DISPOSITION_COMMITTED: u8 = 0x0A;
const CO_TAG_NEXT_CYCLE_ALLOCATED: u8 = 0x0B;
const CO_TAG_LOOP_WAIT_RESUMED: u8 = 0x0C;
const CO_TAG_RETRY_SCHEDULED: u8 = 0x0D;
const CO_TAG_RETRY_ACTIVATED: u8 = 0x0E;
const CO_TAG_RECOVERY_RESUMED: u8 = 0x0F;
const CO_TAG_LOOP_CHECKPOINT_COMMITTED: u8 = 0x10;

/// Codec for [`CommandOutcome`] receipt BLOB.
pub struct CommandOutcomeCodec;

impl StoreCodec<CommandOutcome> for CommandOutcomeCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &CommandOutcome) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        match value {
            CommandOutcome::TaskRunCreated {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_CREATED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunQueued {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_QUEUED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunAdmitted {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_ADMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::AttemptStarted {
                taskrun_id,
                attempt_id,
                new_version,
            } => {
                buf.push(CO_TAG_ATTEMPT_STARTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::TaskRunCompleted {
                taskrun_id,
                new_version,
            } => {
                buf.push(CO_TAG_COMPLETED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::CycleStarted {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_CYCLE_STARTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::ContextCommitted {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_CONTEXT_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::PlanCommitted {
                taskrun_id,
                plan_ref,
                new_version,
            } => {
                buf.push(CO_TAG_PLAN_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                encode_plan_ref(&mut buf, plan_ref.as_ref())?;
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::StepOutcomeRecorded {
                taskrun_id,
                step_id,
                new_version,
            } => {
                buf.push(CO_TAG_STEP_OUTCOME_RECORDED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, step_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopDispositionCommitted {
                taskrun_id,
                cycle_id,
                final_state,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_DISPOSITION_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                buf.push(encode_taskrun_state(*final_state));
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::NextCycleAllocated {
                taskrun_id,
                successor_cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_NEXT_CYCLE_ALLOCATED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, successor_cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopWaitResumed {
                taskrun_id,
                cycle_id,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_WAIT_RESUMED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, cycle_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::RetryScheduled {
                taskrun_id,
                new_attempt_id,
                due_at_unix_us,
                new_version,
            } => {
                buf.push(CO_TAG_RETRY_SCHEDULED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, new_attempt_id.as_bytes());
                write_i64_be(&mut buf, *due_at_unix_us);
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::RetryActivated {
                taskrun_id,
                attempt_id,
                new_version,
            }
            | CommandOutcome::RecoveryResumed {
                taskrun_id,
                attempt_id,
                new_version,
            } => {
                buf.push(if matches!(value, CommandOutcome::RetryActivated { .. }) {
                    CO_TAG_RETRY_ACTIVATED
                } else {
                    CO_TAG_RECOVERY_RESUMED
                });
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, attempt_id.as_bytes());
                write_u64_be(&mut buf, *new_version);
            }
            CommandOutcome::LoopCheckpointCommitted {
                taskrun_id,
                checkpoint_id,
                event_position,
                new_version,
            } => {
                buf.push(CO_TAG_LOOP_CHECKPOINT_COMMITTED);
                write_uuid(&mut buf, taskrun_id.as_bytes());
                write_uuid(&mut buf, checkpoint_id.as_bytes());
                write_u64_be(&mut buf, *event_position);
                write_u64_be(&mut buf, *new_version);
            }
        }
        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<CommandOutcome, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let tag = bytes[pos];
        pos += 1;

        let outcome = match tag {
            CO_TAG_CREATED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCreated {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_QUEUED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunQueued {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_ADMITTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunAdmitted {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_ATTEMPT_STARTED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let att_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::AttemptStarted {
                    taskrun_id: tr_id,
                    attempt_id: att_id,
                    new_version: nv,
                }
            }
            CO_TAG_COMPLETED => {
                let tr_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let nv = read_u64_be(bytes, &mut pos)?;
                CommandOutcome::TaskRunCompleted {
                    taskrun_id: tr_id,
                    new_version: nv,
                }
            }
            CO_TAG_CYCLE_STARTED | CO_TAG_CONTEXT_COMMITTED | CO_TAG_LOOP_WAIT_RESUMED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_version = read_u64_be(bytes, &mut pos)?;
                match tag {
                    CO_TAG_CYCLE_STARTED => CommandOutcome::CycleStarted {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                    CO_TAG_CONTEXT_COMMITTED => CommandOutcome::ContextCommitted {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                    _ => CommandOutcome::LoopWaitResumed {
                        taskrun_id,
                        cycle_id,
                        new_version,
                    },
                }
            }
            CO_TAG_PLAN_COMMITTED => CommandOutcome::PlanCommitted {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                plan_ref: Box::new(decode_plan_ref(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_STEP_OUTCOME_RECORDED => CommandOutcome::StepOutcomeRecorded {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                step_id: StepId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_LOOP_DISPOSITION_COMMITTED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let cycle_id = CycleId::from_bytes(read_uuid(bytes, &mut pos)?);
                let final_state = decode_taskrun_state(bytes, &mut pos)?;
                CommandOutcome::LoopDispositionCommitted {
                    taskrun_id,
                    cycle_id,
                    final_state,
                    new_version: read_u64_be(bytes, &mut pos)?,
                }
            }
            CO_TAG_NEXT_CYCLE_ALLOCATED => CommandOutcome::NextCycleAllocated {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                successor_cycle_id: CycleId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_RETRY_SCHEDULED => CommandOutcome::RetryScheduled {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                new_attempt_id: AttemptId::from_bytes(read_uuid(bytes, &mut pos)?),
                due_at_unix_us: read_i64_be(bytes, &mut pos)?,
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            CO_TAG_RETRY_ACTIVATED | CO_TAG_RECOVERY_RESUMED => {
                let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?);
                let attempt_id = AttemptId::from_bytes(read_uuid(bytes, &mut pos)?);
                let new_version = read_u64_be(bytes, &mut pos)?;
                if tag == CO_TAG_RETRY_ACTIVATED {
                    CommandOutcome::RetryActivated {
                        taskrun_id,
                        attempt_id,
                        new_version,
                    }
                } else {
                    CommandOutcome::RecoveryResumed {
                        taskrun_id,
                        attempt_id,
                        new_version,
                    }
                }
            }
            CO_TAG_LOOP_CHECKPOINT_COMMITTED => CommandOutcome::LoopCheckpointCommitted {
                taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, &mut pos)?),
                checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, &mut pos)?),
                event_position: read_u64_be(bytes, &mut pos)?,
                new_version: read_u64_be(bytes, &mut pos)?,
            },
            _ => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "CommandOutcome",
                });
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(outcome)
    }
}

// ── ConversationReceipt codec ────────────────────────────────────────────

/// Codec for durable create-conversation receipts.
pub struct ConversationReceiptCodec;

impl StoreCodec<ConversationReceipt> for ConversationReceiptCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &ConversationReceipt) -> Result<Vec<u8>, StoreCodecError> {
        let mut buffer = Vec::with_capacity(50);
        write_u16_be(&mut buffer, Self::CODEC_VERSION);
        write_uuid(&mut buffer, value.conversation_id.as_bytes());
        write_uuid(&mut buffer, value.workspace_id.as_bytes());
        write_u64_be(&mut buffer, value.new_version);
        write_i64_be(&mut buffer, value.committed_at.as_unix_micros());
        Ok(buffer)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ConversationReceipt, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let conversation_id = ConversationId::from_bytes(read_uuid(bytes, &mut position)?);
        let workspace_id = WorkspaceId::from_bytes(read_uuid(bytes, &mut position)?);
        conversation_id
            .to_string()
            .parse::<ConversationId>()
            .map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt conversation UUIDv7",
            })?;
        workspace_id
            .to_string()
            .parse::<WorkspaceId>()
            .map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt workspace UUIDv7",
            })?;
        let new_version = read_u64_be(bytes, &mut position)?;
        let committed_at = gocode_domain::timestamp::Timestamp::from_unix_micros(read_i64_be(
            bytes,
            &mut position,
        )?);
        if committed_at.as_unix_micros() < 0 {
            return Err(StoreCodecError::UnknownTag {
                tag: 0,
                context: "ConversationReceipt negative commit timestamp",
            });
        }
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(ConversationReceipt {
            conversation_id,
            workspace_id,
            new_version,
            committed_at,
        })
    }
}

// ── IdempotencyScope codec ───────────────────────────────────────────────

/// Codec for [`IdempotencyScope`] — stored in `command_receipts`.
pub struct IdempotencyScopeCodec;

impl StoreCodec<IdempotencyScope> for IdempotencyScopeCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &IdempotencyScope) -> Result<Vec<u8>, StoreCodecError> {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, Self::CODEC_VERSION);

        // runtime_authority_id (length-prefixed ASCII)
        let ra_bytes = value.runtime_authority_id.0.as_bytes();
        write_len_prefixed(&mut buf, ra_bytes);

        // principal_id (length-prefixed ASCII)
        let p_bytes = value.principal_id.0.as_bytes();
        write_len_prefixed(&mut buf, p_bytes);

        // operation (u8)
        buf.push(value.operation as u8);

        // aggregate_scope
        match &value.aggregate_scope {
            AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            } => {
                buf.push(0x00); // tag: NewTaskRun
                write_uuid(&mut buf, conversation_id.as_bytes());
                write_uuid(&mut buf, workspace_id.as_bytes());
            }
            AggregateScope::ExistingTaskRun { taskrun_id } => {
                buf.push(0x01); // tag: ExistingTaskRun
                write_uuid(&mut buf, taskrun_id.as_bytes());
            }
            AggregateScope::NewConversation {
                conversation_id,
                workspace_id,
            } => {
                buf.push(0x02);
                write_uuid(&mut buf, conversation_id.as_bytes());
                write_uuid(&mut buf, workspace_id.as_bytes());
            }
        }

        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<IdempotencyScope, StoreCodecError> {
        let mut pos = 0usize;
        let version = read_u16_be(bytes, &mut pos)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }

        let ra_bytes = read_len_prefixed(bytes, &mut pos)?;
        let runtime_authority_id = gocode_application::ports::RuntimeAuthorityId(
            String::from_utf8(ra_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "RuntimeAuthorityId (invalid UTF-8)",
            })?,
        );

        let p_bytes = read_len_prefixed(bytes, &mut pos)?;
        let principal_id = gocode_application::ports::PrincipalId(
            String::from_utf8(p_bytes.to_vec()).map_err(|_| StoreCodecError::UnknownTag {
                tag: 0,
                context: "PrincipalId (invalid UTF-8)",
            })?,
        );

        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let op_tag = bytes[pos];
        pos += 1;
        let operation = match op_tag {
            1 => OperationTag::CreateTaskRun,
            2 => OperationTag::Queue,
            3 => OperationTag::Admit,
            4 => OperationTag::StartAttempt,
            5 => OperationTag::Complete,
            6 => OperationTag::CreateConversation,
            7 => OperationTag::StartLoopCycle,
            8 => OperationTag::CommitContext,
            9 => OperationTag::CommitPlan,
            10 => OperationTag::RecordStepOutcome,
            11 => OperationTag::CompleteLoopCycle,
            12 => OperationTag::CreateNextCycle,
            13 => OperationTag::ScheduleRetry,
            14 => OperationTag::ActivateScheduledRetryAttempt,
            15 => OperationTag::CommitRecoveryResume,
            16 => OperationTag::CommitLoopCheckpoint,
            17 => OperationTag::ResumeLoopWait,
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "OperationTag",
                });
            }
        };

        if pos >= bytes.len() {
            return Err(StoreCodecError::Truncated);
        }
        let scope_tag = bytes[pos];
        pos += 1;
        let aggregate_scope = match scope_tag {
            0x00 => {
                let conv_bytes = read_uuid(bytes, &mut pos)?;
                let ws_bytes = read_uuid(bytes, &mut pos)?;
                AggregateScope::NewTaskRun {
                    conversation_id: ConversationId::from_bytes(conv_bytes),
                    workspace_id: WorkspaceId::from_bytes(ws_bytes),
                }
            }
            0x01 => {
                let tr_bytes = read_uuid(bytes, &mut pos)?;
                AggregateScope::ExistingTaskRun {
                    taskrun_id: TaskRunId::from_bytes(tr_bytes),
                }
            }
            0x02 => {
                let conversation_id = ConversationId::from_bytes(read_uuid(bytes, &mut pos)?);
                let workspace_id = WorkspaceId::from_bytes(read_uuid(bytes, &mut pos)?);
                AggregateScope::NewConversation {
                    conversation_id,
                    workspace_id,
                }
            }
            t => {
                return Err(StoreCodecError::UnknownTag {
                    tag: t,
                    context: "AggregateScope",
                });
            }
        };

        if pos < bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - pos,
            });
        }

        Ok(IdempotencyScope {
            runtime_authority_id,
            principal_id,
            operation,
            aggregate_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TR_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const CONV_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const WS_ID: &str = "018f2e3a-7000-7000-8000-000000000004";

    fn phase5_context_ref() -> ContextManifestRef {
        ContextManifestRef {
            manifest_id: TR_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            attempt_id: ATT_ID.parse().unwrap(),
            cycle_id: CONV_ID.parse().unwrap(),
            revision: 1,
            policy_revision: "context-v1".into(),
            integrity_digest: IntegrityDigest::from_bytes([1; 32]),
        }
    }

    fn phase5_budget_ref() -> BudgetReservationRef {
        BudgetReservationRef {
            reservation_id: WS_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            attempt_id: ATT_ID.parse().unwrap(),
            retry_ordinal: 1,
            reservation_digest: IntegrityDigest::from_bytes([2; 32]),
        }
    }

    fn phase5_plan_ref() -> PlanRevisionRef {
        PlanRevisionRef {
            plan_id: WS_ID.parse().unwrap(),
            taskrun_id: TR_ID.parse().unwrap(),
            cycle_id: CONV_ID.parse().unwrap(),
            revision: 2,
            context_manifest_ref: phase5_context_ref(),
            expected_proposal_indexes: vec![0],
            proposal_batch_digest: IntegrityDigest::from_bytes([3; 32]),
            planning_policy_ref: ResultRef::new(
                TR_ID.parse().unwrap(),
                "application/json",
                IntegrityDigest::from_bytes([4; 32]),
            )
            .unwrap(),
            planning_budget_ref: phase5_budget_ref(),
            parent_ref: Some(PlanParentRef {
                plan_id: WS_ID.parse().unwrap(),
                revision: 1,
                integrity_digest: IntegrityDigest::from_bytes([5; 32]),
            }),
            integrity_digest: IntegrityDigest::from_bytes([6; 32]),
        }
    }

    fn phase5_step_ref() -> StepOutcomeRef {
        StepOutcomeRef {
            cycle_id: CONV_ID.parse().unwrap(),
            proposal_index: 0,
            step_id: WS_ID.parse().unwrap(),
            outcome_digest: IntegrityDigest::from_bytes([7; 32]),
        }
    }

    // ── TaskRunEvent round-trip ────────────────────────────────────────

    #[test]
    fn test_taskrun_event_codec_roundtrip_created() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCreated;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn phase5_taskrun_event_codec_roundtrips_all_thirteen_tags() {
        let cycle_id: CycleId = CONV_ID.parse().unwrap();
        let attempt_id: AttemptId = ATT_ID.parse().unwrap();
        let checkpoint_id: CheckpointId = WS_ID.parse().unwrap();
        let digest = IntegrityDigest::from_bytes([8; 32]);
        let step_ref = phase5_step_ref();
        let wake_evidence = WakeEvidenceRef {
            cycle_id,
            condition_digest: IntegrityDigest::from_bytes([9; 32]),
            source: WakeEvidenceSource::Approval,
            evidence_id: WS_ID.parse().unwrap(),
            evidence_digest: IntegrityDigest::from_bytes([10; 32]),
            observed_at_unix_us: 100,
            authority_revision: "approval-v1".into(),
        };
        let events = vec![
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence: 0,
                parent_cycle_id: None,
            },
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref: phase5_context_ref(),
            },
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref: phase5_plan_ref(),
                input_digest: IntegrityDigest::from_bytes([11; 32]),
                output_digest: IntegrityDigest::from_bytes([12; 32]),
                expected_proposal_indexes: vec![0],
            },
            TaskRunEvent::StepOutcomeRecorded {
                cycle_id,
                outcome: StepOutcomeRecord {
                    proposal_index: 0,
                    step_id: WS_ID.parse().unwrap(),
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: Some(
                        ResultRef::new(
                            TR_ID.parse().unwrap(),
                            "text/plain",
                            IntegrityDigest::from_bytes([13; 32]),
                        )
                        .unwrap(),
                    ),
                    effect_id: None,
                    evidence_digests: vec![IntegrityDigest::from_bytes([14; 32])],
                },
            },
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition: LoopDisposition::Wait {
                    reason: "approval".into(),
                    wake_condition: WakeCondition {
                        kind: WakeConditionKind::Approval,
                        condition_ref: "approval:1".into(),
                        condition_digest: IntegrityDigest::from_bytes([9; 32]),
                    },
                },
            },
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id: cycle_id,
                successor_cycle_id: WS_ID.parse().unwrap(),
                attempt_id,
                sequence: 1,
            },
            TaskRunEvent::RetryScheduled {
                ordinal: 1,
                old_attempt_id: attempt_id,
                new_attempt_id: WS_ID.parse().unwrap(),
                abandoned_cycle_id: cycle_id,
                step_outcome_ref: step_ref.clone(),
                retry_policy_digest: digest,
                budget_reservation_ref: phase5_budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 125,
            },
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position: 20,
                body: LoopCheckpointBody {
                    schema_version: "1".into(),
                    cycle_id,
                    attempt_id,
                    plan_revision_ref: Some(phase5_plan_ref()),
                    context_manifest_ref: Some(phase5_context_ref()),
                    step_outcome_refs: vec![step_ref],
                },
                integrity_digest: digest,
            },
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal: 1,
                attempt_id: WS_ID.parse().unwrap(),
                activated_at_unix_us: 125,
            },
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id: WS_ID.parse().unwrap(),
                new_generation: 1,
                abandoned_cycle_id: Some(cycle_id),
                context_manifest_ref: phase5_context_ref(),
                checkpoint_ref: CheckpointRef {
                    checkpoint_id,
                    event_position: 20,
                    integrity_digest: digest,
                },
                reconciliation_ref: ReconciliationResultRef {
                    reconciliation_run_id: WS_ID.parse().unwrap(),
                    taskrun_id: TR_ID.parse().unwrap(),
                    predecessor_attempt_id: attempt_id,
                    recovery_generation: 0,
                    reconciled_stream_position: 19,
                    status: ReconciliationStatus::Reconciled,
                    unresolved_effect_count: 0,
                    result_digest: digest,
                },
            },
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position: 20,
                integrity_digest: digest,
            },
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position: 20,
                integrity_digest: digest,
            },
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref: wake_evidence,
            },
        ];

        let codec = TaskRunEventCodec;
        let expected_tags = 0x15u8..=0x21;
        for (event, expected_tag) in events.iter().zip(expected_tags) {
            let bytes = codec.encode(event).unwrap();
            assert_eq!(bytes[2], expected_tag);
            assert_eq!(codec.decode(&bytes).unwrap(), *event);

            let mut unsupported = bytes.clone();
            unsupported[1] = 2;
            assert!(matches!(
                codec.decode(&unsupported),
                Err(StoreCodecError::UnsupportedVersion { .. })
            ));

            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(matches!(
                codec.decode(&trailing),
                Err(StoreCodecError::TrailingBytes { .. })
            ));

            assert!(matches!(
                codec.decode(&bytes[..bytes.len() - 1]),
                Err(StoreCodecError::Truncated)
            ));
        }
    }

    #[test]
    fn phase5_command_outcome_codec_roundtrips_tags_six_through_sixteen() {
        let taskrun_id: TaskRunId = TR_ID.parse().unwrap();
        let cycle_id: CycleId = CONV_ID.parse().unwrap();
        let attempt_id: AttemptId = ATT_ID.parse().unwrap();
        let checkpoint_id: CheckpointId = WS_ID.parse().unwrap();
        let outcomes = vec![
            CommandOutcome::CycleStarted {
                taskrun_id,
                cycle_id,
                new_version: 1,
            },
            CommandOutcome::ContextCommitted {
                taskrun_id,
                cycle_id,
                new_version: 2,
            },
            CommandOutcome::PlanCommitted {
                taskrun_id,
                plan_ref: Box::new(phase5_plan_ref()),
                new_version: 3,
            },
            CommandOutcome::StepOutcomeRecorded {
                taskrun_id,
                step_id: WS_ID.parse().unwrap(),
                new_version: 4,
            },
            CommandOutcome::LoopDispositionCommitted {
                taskrun_id,
                cycle_id,
                final_state: TaskRunState::Waiting,
                new_version: 6,
            },
            CommandOutcome::NextCycleAllocated {
                taskrun_id,
                successor_cycle_id: WS_ID.parse().unwrap(),
                new_version: 7,
            },
            CommandOutcome::LoopWaitResumed {
                taskrun_id,
                cycle_id,
                new_version: 9,
            },
            CommandOutcome::RetryScheduled {
                taskrun_id,
                new_attempt_id: attempt_id,
                due_at_unix_us: 100,
                new_version: 10,
            },
            CommandOutcome::RetryActivated {
                taskrun_id,
                attempt_id,
                new_version: 11,
            },
            CommandOutcome::RecoveryResumed {
                taskrun_id,
                attempt_id,
                new_version: 12,
            },
            CommandOutcome::LoopCheckpointCommitted {
                taskrun_id,
                checkpoint_id,
                event_position: 13,
                new_version: 15,
            },
        ];
        let codec = CommandOutcomeCodec;

        for (outcome, expected_tag) in outcomes.iter().zip(0x06u8..=0x10) {
            let bytes = codec.encode(outcome).unwrap();
            assert_eq!(bytes[2], expected_tag);
            assert_eq!(codec.decode(&bytes).unwrap(), *outcome);

            let mut unsupported = bytes.clone();
            unsupported[1] = 2;
            assert!(matches!(
                codec.decode(&unsupported),
                Err(StoreCodecError::UnsupportedVersion { .. })
            ));

            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(matches!(
                codec.decode(&trailing),
                Err(StoreCodecError::TrailingBytes { .. })
            ));

            assert!(matches!(
                codec.decode(&bytes[..bytes.len() - 1]),
                Err(StoreCodecError::Truncated)
            ));
        }
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_queued() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunQueued;
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_attempt_started() {
        let codec = TaskRunEventCodec;
        let aid: AttemptId = ATT_ID.parse().unwrap();
        let original = TaskRunEvent::AttemptStarted { attempt_id: aid };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_success() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_roundtrip_completed_failure() {
        let codec = TaskRunEventCodec;
        let original = TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Failure {
                reason: "test error".into(),
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_version() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        // Corrupt version bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::UnsupportedVersion { .. }));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_unknown_tag() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes[2] = 0xFF;
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::UnknownTag { .. }));
    }

    #[test]
    fn test_taskrun_event_codec_rejects_trailing_bytes() {
        let codec = TaskRunEventCodec;
        let mut bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
        bytes.push(0x00);
        let err = codec.decode(&bytes).unwrap_err();
        assert!(matches!(err, StoreCodecError::TrailingBytes { .. }));
    }

    // ── ConversationEvent round-trip ──────────────────────────────────

    #[test]
    fn conversation_event_codec_created_has_stable_bytes() {
        let codec = ConversationEventCodec;
        let workspace_id: WorkspaceId = WS_ID.parse().unwrap();
        let original = ConversationEvent::ConversationCreated { workspace_id };

        let bytes = codec.encode(&original).unwrap();

        let mut expected = vec![0x00, 0x01, TAG_CONVERSATION_CREATED];
        expected.extend_from_slice(workspace_id.as_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(codec.decode(&bytes).unwrap(), original);
    }

    #[test]
    fn conversation_event_codec_closed_has_stable_bytes() {
        let codec = ConversationEventCodec;
        let bytes = codec
            .encode(&ConversationEvent::ConversationClosed)
            .unwrap();

        assert_eq!(bytes, [0x00, 0x01, TAG_CONVERSATION_CLOSED]);
        assert_eq!(
            codec.decode(&bytes).unwrap(),
            ConversationEvent::ConversationClosed
        );
    }

    #[test]
    fn conversation_event_codec_rejects_unknown_version_tag_and_trailing_bytes() {
        let codec = ConversationEventCodec;
        let mut unknown_version = vec![0xff, 0xff, TAG_CONVERSATION_CLOSED];
        assert!(matches!(
            codec.decode(&unknown_version),
            Err(StoreCodecError::UnsupportedVersion { .. })
        ));

        unknown_version[0] = 0x00;
        unknown_version[1] = 0x01;
        unknown_version[2] = 0xff;
        assert!(matches!(
            codec.decode(&unknown_version),
            Err(StoreCodecError::UnknownTag { .. })
        ));

        let mut trailing = codec
            .encode(&ConversationEvent::ConversationClosed)
            .unwrap();
        trailing.push(0);
        assert!(matches!(
            codec.decode(&trailing),
            Err(StoreCodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn conversation_event_codec_rejects_non_uuid_v7_workspace() {
        let codec = ConversationEventCodec;
        let mut bytes = vec![0x00, 0x01, TAG_CONVERSATION_CREATED];
        bytes.extend_from_slice(&[0; 16]);

        assert!(matches!(
            codec.decode(&bytes),
            Err(StoreCodecError::UnknownTag {
                context: "ConversationCreated workspace UUIDv7",
                ..
            })
        ));
    }

    // ── CommandOutcome round-trip ──────────────────────────────────────

    #[test]
    fn test_command_outcome_codec_roundtrip_created() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_command_outcome_codec_roundtrip_attempt_started() {
        let codec = CommandOutcomeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let att_id: AttemptId = ATT_ID.parse().unwrap();
        let original = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn conversation_receipt_codec_has_stable_roundtrip_bytes() {
        let codec = ConversationReceiptCodec;
        let conversation_id: ConversationId = CONV_ID.parse().unwrap();
        let workspace_id: WorkspaceId = WS_ID.parse().unwrap();
        let receipt = ConversationReceipt {
            conversation_id,
            workspace_id,
            new_version: 1,
            committed_at: gocode_domain::timestamp::Timestamp::from_unix_micros(1_234_567),
        };

        let bytes = codec.encode(&receipt).unwrap();

        let mut expected = vec![0, 1];
        expected.extend_from_slice(conversation_id.as_bytes());
        expected.extend_from_slice(workspace_id.as_bytes());
        expected.extend_from_slice(&1_u64.to_be_bytes());
        expected.extend_from_slice(&1_234_567_i64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(codec.decode(&bytes).unwrap(), receipt);
    }

    #[test]
    fn conversation_receipt_codec_rejects_negative_timestamp_and_trailing_bytes() {
        let codec = ConversationReceiptCodec;
        let receipt = ConversationReceipt {
            conversation_id: CONV_ID.parse().unwrap(),
            workspace_id: WS_ID.parse().unwrap(),
            new_version: 1,
            committed_at: gocode_domain::timestamp::Timestamp::from_unix_micros(1),
        };
        let mut negative = codec.encode(&receipt).unwrap();
        let timestamp_start = negative.len() - 8;
        negative[timestamp_start..].copy_from_slice(&(-1_i64).to_be_bytes());
        assert!(matches!(
            codec.decode(&negative),
            Err(StoreCodecError::UnknownTag {
                context: "ConversationReceipt negative commit timestamp",
                ..
            })
        ));

        let mut trailing = codec.encode(&receipt).unwrap();
        trailing.push(0);
        assert!(matches!(
            codec.decode(&trailing),
            Err(StoreCodecError::TrailingBytes { remaining: 1 })
        ));
    }

    // ── IdempotencyScope round-trip ────────────────────────────────────

    #[test]
    fn test_idempotency_scope_codec_roundtrip_existing() {
        let codec = IdempotencyScopeCodec;
        let tr_id: TaskRunId = TR_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: gocode_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: gocode_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::Queue,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id: tr_id },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_idempotency_scope_codec_roundtrip_new() {
        let codec = IdempotencyScopeCodec;
        let conv_id: ConversationId = CONV_ID.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID.parse().unwrap();
        let original = IdempotencyScope {
            runtime_authority_id: gocode_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: gocode_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id: conv_id,
                workspace_id: ws_id,
            },
        };
        let bytes = codec.encode(&original).unwrap();
        let decoded = codec.decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn idempotency_scope_codec_roundtrips_new_conversation() {
        let codec = IdempotencyScopeCodec;
        let original = IdempotencyScope {
            runtime_authority_id: gocode_application::ports::RuntimeAuthorityId("host-1".into()),
            principal_id: gocode_application::ports::PrincipalId("user-1".into()),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: CONV_ID.parse().unwrap(),
                workspace_id: WS_ID.parse().unwrap(),
            },
        };

        let bytes = codec.encode(&original).unwrap();

        assert_eq!(codec.decode(&bytes).unwrap(), original);
    }
}

//! Phase 5 Codec Tests — malformed-input rejection and golden byte stability.
//!
//! Ensures the store codec rejects: unknown version, unknown tag, trailing bytes,
//! and truncated payloads for Phase 5 TaskRunEvent and CommandOutcome variants.
//! Additionally verifies existing golden tags (0x01..0x14) remain unchanged.

use gocode_application::commands::CommandOutcome;
use gocode_domain::command::TerminalResult;
use gocode_domain::id::*;
use gocode_domain::task_run::TaskRunEvent;
use gocode_store::codec::{CommandOutcomeCodec, StoreCodec, StoreCodecError, TaskRunEventCodec};

const TASK: &str = "018f2e3a-7000-7000-8000-000000000001";
const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000002";

// ═══════════════════════════════════════════════════════════════════════
// TaskRunEvent malformed-input tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn phase5_taskrun_event_rejects_unknown_version() {
    let codec = TaskRunEventCodec;
    let event = TaskRunEvent::TaskRunCreated;
    let mut bytes = codec.encode(&event).unwrap();
    bytes[1] = 0xFF; // corrupt version byte
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::UnsupportedVersion { .. }));
}

#[test]
fn phase5_taskrun_event_rejects_unknown_tag() {
    let codec = TaskRunEventCodec;
    let event = TaskRunEvent::TaskRunCreated;
    let mut bytes = codec.encode(&event).unwrap();
    bytes[2] = 0xFF; // corrupt tag byte
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::UnknownTag { .. }));
}

#[test]
fn phase5_taskrun_event_rejects_trailing_bytes() {
    let codec = TaskRunEventCodec;
    let event = TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Success,
    };
    let mut bytes = codec.encode(&event).unwrap();
    bytes.push(0x00); // trailing byte
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::TrailingBytes { .. }));
}

#[test]
fn phase5_taskrun_event_rejects_truncated_bytes() {
    let codec = TaskRunEventCodec;
    let event = TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Success,
    };
    let bytes = codec.encode(&event).unwrap();
    let truncated = &bytes[..bytes.len() - 1];
    let err = codec.decode(truncated).unwrap_err();
    assert!(matches!(err, StoreCodecError::Truncated));
}

// ═══════════════════════════════════════════════════════════════════════
// CommandOutcome malformed-input tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn phase5_command_outcome_rejects_unknown_version() {
    let codec = CommandOutcomeCodec;
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let outcome = CommandOutcome::TaskRunCreated {
        taskrun_id,
        new_version: 1,
    };
    let mut bytes = codec.encode(&outcome).unwrap();
    bytes[1] = 0xFF;
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::UnsupportedVersion { .. }));
}

#[test]
fn phase5_command_outcome_rejects_unknown_tag() {
    let codec = CommandOutcomeCodec;
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let outcome = CommandOutcome::TaskRunCreated {
        taskrun_id,
        new_version: 1,
    };
    let mut bytes = codec.encode(&outcome).unwrap();
    bytes[2] = 0xFF;
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::UnknownTag { .. }));
}

#[test]
fn phase5_command_outcome_rejects_trailing_bytes() {
    let codec = CommandOutcomeCodec;
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let outcome = CommandOutcome::TaskRunCompleted {
        taskrun_id,
        new_version: 5,
    };
    let mut bytes = codec.encode(&outcome).unwrap();
    bytes.push(0x00);
    let err = codec.decode(&bytes).unwrap_err();
    assert!(matches!(err, StoreCodecError::TrailingBytes { .. }));
}

#[test]
fn phase5_command_outcome_rejects_truncated_bytes() {
    let codec = CommandOutcomeCodec;
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let outcome = CommandOutcome::TaskRunCompleted {
        taskrun_id,
        new_version: 5,
    };
    let bytes = codec.encode(&outcome).unwrap();
    let truncated = &bytes[..bytes.len() - 1];
    let err = codec.decode(truncated).unwrap_err();
    assert!(matches!(err, StoreCodecError::Truncated));
}

// ═══════════════════════════════════════════════════════════════════════
// Golden byte stability — existing tags unchanged
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn phase5_golden_tag_taskrun_created() {
    let codec = TaskRunEventCodec;
    let bytes = codec.encode(&TaskRunEvent::TaskRunCreated).unwrap();
    assert_eq!(bytes[2], 0x01);
    assert_eq!(codec.decode(&bytes).unwrap(), TaskRunEvent::TaskRunCreated);
}

#[test]
fn phase5_golden_tag_taskrun_queued() {
    let codec = TaskRunEventCodec;
    let bytes = codec.encode(&TaskRunEvent::TaskRunQueued).unwrap();
    assert_eq!(bytes[2], 0x02);
    assert_eq!(codec.decode(&bytes).unwrap(), TaskRunEvent::TaskRunQueued);
}

#[test]
fn phase5_golden_tag_taskrun_admitted() {
    let codec = TaskRunEventCodec;
    let bytes = codec.encode(&TaskRunEvent::TaskRunAdmitted).unwrap();
    assert_eq!(bytes[2], 0x03);
    assert_eq!(codec.decode(&bytes).unwrap(), TaskRunEvent::TaskRunAdmitted);
}

#[test]
fn phase5_golden_tag_attempt_started() {
    let codec = TaskRunEventCodec;
    let aid: AttemptId = ATT_ID.parse().unwrap();
    let event = TaskRunEvent::AttemptStarted { attempt_id: aid };
    let bytes = codec.encode(&event).unwrap();
    assert_eq!(bytes[2], 0x04);
    assert_eq!(codec.decode(&bytes).unwrap(), event);
}

#[test]
fn phase5_golden_tag_wait_started() {
    let codec = TaskRunEventCodec;
    let bytes = codec.encode(&TaskRunEvent::WaitStarted).unwrap();
    assert_eq!(bytes[2], 0x05);
    assert_eq!(codec.decode(&bytes).unwrap(), TaskRunEvent::WaitStarted);
}

#[test]
fn phase5_golden_tags_resumed_through_reconciled() {
    let codec = TaskRunEventCodec;
    let events = [
        TaskRunEvent::Resumed,
        TaskRunEvent::RetryStarted {
            attempt_id: ATT_ID.parse().unwrap(),
        },
        TaskRunEvent::RetryCompleted {
            attempt_id: ATT_ID.parse().unwrap(),
        },
        TaskRunEvent::CheckpointStarted,
        TaskRunEvent::CheckpointCommitted,
        TaskRunEvent::CancellationRequested,
        TaskRunEvent::CancellationCompleted,
        TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        },
        TaskRunEvent::TaskRunFailed {
            reason: "test".into(),
        },
        TaskRunEvent::BudgetExhausted,
        TaskRunEvent::PolicyDenied,
        TaskRunEvent::ReconciliationStarted,
        TaskRunEvent::Reconciled,
    ];
    let expected_tags = 0x06u8..=0x12;
    for (event, expected_tag) in events.iter().zip(expected_tags) {
        let bytes = codec.encode(event).unwrap();
        assert_eq!(bytes[2], expected_tag);
        assert_eq!(codec.decode(&bytes).unwrap(), *event);
    }
}

#[test]
fn phase5_golden_tags_unrecoverable_and_cancelled() {
    let codec = TaskRunEventCodec;
    let events = [TaskRunEvent::Unrecoverable, TaskRunEvent::TaskRunCancelled];
    let expected_tags = [0x13u8, 0x14];
    for (event, &expected_tag) in events.iter().zip(expected_tags.iter()) {
        let bytes = codec.encode(event).unwrap();
        assert_eq!(bytes[2], expected_tag);
        assert_eq!(codec.decode(&bytes).unwrap(), *event);
    }
}

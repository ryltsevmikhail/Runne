//! Regression tests for `generation_matches` correlation ordering.

use super::outcome::{GenerationAssistant, GenerationTerminal, LedgerMessage, MessageRole};
use super::{CanonicalMutationOutcome, NormalizedMutationCommand};
use crate::BoundedCanonicalId;

const CONVERSATION_ID: &str = "7b2a9c1e-5d3f-7a4b-8c6d-2e1f0a9b8c7d";
const TASK_RUN_ID: &str = "1a2b3c4d-5e6f-7a1b-8c2d-3e4f5a6b7c8d";
const ATTEMPT_ID: &str = "0f1e2d3c-4b5a-7968-8a7b-6c5d4e3f2a1b";
/// Mirrors the daemon's v7 minting: unix-ms in the high bytes, monotonic
/// counter in the low bytes (`StoreTransaction::generate_uuid`).
const USER_MESSAGE_ID: &str = "018f3a2b-7c1d-7a2f-8b3e-4c5d6e7f1001";
const ASSISTANT_MESSAGE_ID_AFTER: &str = "018f3a2b-7c1d-7a2f-8b3e-4c5d6e7f1002";
const ASSISTANT_MESSAGE_ID_BEFORE: &str = "018f3a2b-7c1d-7a2f-8b3e-4c5d6e7f1000";
/// Same-millisecond pair from the captured `MutationUnavailable` repro.
const SAME_MILLISECOND: u64 = 1_789_929_449_260;

fn bounded_id(value: &str) -> BoundedCanonicalId {
    BoundedCanonicalId::parse(value.as_bytes()).expect("canonical v7 id")
}

#[test]
fn successor_v2_codec_keeps_both_versions_and_legacy_tag_is_inert() {
    let predecessor = bounded_id(TASK_RUN_ID);
    let successor = bounded_id("2a3b4c5d-6e7f-7a1b-9c2d-3e4f5a6b7c8d");
    let outcome = CanonicalMutationOutcome::TaskRunUnknownSuccessorCreated {
        predecessor_task_run_id: predecessor.clone(),
        successor_task_run_id: successor.clone(),
        predecessor_version: 6,
        successor_version: 2,
    };
    let bytes = outcome.encode().expect("encode v2 successor");
    assert_eq!(bytes[1], 25);
    assert_eq!(CanonicalMutationOutcome::decode(&bytes).unwrap(), outcome);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CanonicalMutationOutcome::decode(&trailing).is_err());
    let mut wrong_successor_version = bytes;
    *wrong_successor_version.last_mut().unwrap() = 3;
    assert!(CanonicalMutationOutcome::decode(&wrong_successor_version).is_err());

    let legacy = CanonicalMutationOutcome::TaskRunUnknownSuccessorCreatedLegacy {
        predecessor_task_run_id: predecessor,
        successor_task_run_id: successor,
        new_version: 7,
    };
    let legacy_bytes = legacy.encode().expect("encode legacy v1 outcome");
    assert_eq!(legacy_bytes[1], 24);
    assert_eq!(
        CanonicalMutationOutcome::decode(&legacy_bytes).unwrap(),
        legacy
    );
}

fn ledger_message(message_id: &str, role: MessageRole, committed_at: u64) -> LedgerMessage {
    LedgerMessage {
        message_id: bounded_id(message_id),
        role,
        task_run_id: bounded_id(TASK_RUN_ID),
        attempt_id: bounded_id(ATTEMPT_ID),
        text: if role == MessageRole::User {
            "first protected message".into()
        } else {
            "first protected reply".into()
        },
        committed_at,
    }
}

fn generation_outcome(user: LedgerMessage, assistant: LedgerMessage) -> CanonicalMutationOutcome {
    CanonicalMutationOutcome::Generation {
        terminal: GenerationTerminal::Completed,
        conversation_id: bounded_id(CONVERSATION_ID),
        task_run_id: bounded_id(TASK_RUN_ID),
        attempt_id: bounded_id(ATTEMPT_ID),
        conversation_stream_version: 3,
        task_run_stream_version: 5,
        user_message: user,
        assistant: Box::new(GenerationAssistant::Completed(assistant)),
    }
}

#[test]
fn generation_failure_reasons_keep_legacy_tag_and_round_trip_new_tags() {
    for (reason, expected_tag, taskrun_version) in [
        (
            super::outcome::GenerationFailureReason::ProviderOutputRejected,
            1,
            5,
        ),
        (
            super::outcome::GenerationFailureReason::ProviderExecutionRejected,
            2,
            5,
        ),
        (
            super::outcome::GenerationFailureReason::ProviderExecutionFailed,
            3,
            5,
        ),
        (
            super::outcome::GenerationFailureReason::ProviderAccountingUnknown,
            5,
            5,
        ),
        (super::outcome::GenerationFailureReason::Cancelled, 4, 6),
    ] {
        let outcome = CanonicalMutationOutcome::Generation {
            terminal: GenerationTerminal::Rejected,
            conversation_id: bounded_id(CONVERSATION_ID),
            task_run_id: bounded_id(TASK_RUN_ID),
            attempt_id: bounded_id(ATTEMPT_ID),
            conversation_stream_version: 3,
            task_run_stream_version: taskrun_version,
            user_message: ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
            assistant: Box::new(GenerationAssistant::Rejected {
                reserved_message_id: bounded_id(ASSISTANT_MESSAGE_ID_AFTER),
                reason,
            }),
        };
        let encoded = outcome.encode().expect("encode failure outcome");
        assert_eq!(encoded.last(), Some(&expected_tag));
        assert_eq!(
            CanonicalMutationOutcome::decode(&encoded).expect("decode failure outcome"),
            outcome.clone()
        );
        assert!(outcome.correlates_to_command(&generate_text_command()));
        if reason == super::outcome::GenerationFailureReason::Cancelled {
            let mut unknown_reason = encoded;
            *unknown_reason.last_mut().unwrap() = 0xff;
            assert!(CanonicalMutationOutcome::decode(&unknown_reason).is_err());
        }
    }
}

#[test]
fn generation_cancelled_reason_requires_rejected_v6() {
    for (terminal, taskrun_version, reason) in [
        (
            GenerationTerminal::Rejected,
            5,
            super::outcome::GenerationFailureReason::Cancelled,
        ),
        (
            GenerationTerminal::Rejected,
            6,
            super::outcome::GenerationFailureReason::ProviderExecutionFailed,
        ),
        (
            GenerationTerminal::Prohibited,
            6,
            super::outcome::GenerationFailureReason::Cancelled,
        ),
        (
            GenerationTerminal::Completed,
            6,
            super::outcome::GenerationFailureReason::Cancelled,
        ),
        (
            GenerationTerminal::Prohibited,
            5,
            super::outcome::GenerationFailureReason::ProviderAccountingUnknown,
        ),
        (
            GenerationTerminal::Completed,
            5,
            super::outcome::GenerationFailureReason::ProviderAccountingUnknown,
        ),
    ] {
        let outcome = CanonicalMutationOutcome::Generation {
            terminal,
            conversation_id: bounded_id(CONVERSATION_ID),
            task_run_id: bounded_id(TASK_RUN_ID),
            attempt_id: bounded_id(ATTEMPT_ID),
            conversation_stream_version: 3,
            task_run_stream_version: taskrun_version,
            user_message: ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
            assistant: Box::new(GenerationAssistant::Rejected {
                reserved_message_id: bounded_id(ASSISTANT_MESSAGE_ID_AFTER),
                reason,
            }),
        };
        assert!(outcome.encode().is_err());
    }
}

fn generate_text_command() -> NormalizedMutationCommand {
    NormalizedMutationCommand::GenerateText {
        conversation_id: bounded_id(CONVERSATION_ID),
        expected_version: 1,
        text: "first protected message".into(),
    }
}

#[test]
fn same_millisecond_generation_correlates() {
    let outcome = generation_outcome(
        ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
        ledger_message(
            ASSISTANT_MESSAGE_ID_AFTER,
            MessageRole::Assistant,
            SAME_MILLISECOND,
        ),
    );
    assert!(
        outcome.correlates_to_command(&generate_text_command()),
        "a generation whose user and assistant events share one millisecond \
         must correlate when the monotonic message ids prove the order"
    );
}

#[test]
fn cross_millisecond_generation_correlates() {
    let outcome = generation_outcome(
        ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
        ledger_message(
            ASSISTANT_MESSAGE_ID_AFTER,
            MessageRole::Assistant,
            SAME_MILLISECOND + 1,
        ),
    );
    assert!(
        outcome.correlates_to_command(&generate_text_command()),
        "a generation committed strictly after the user millisecond must correlate"
    );
}

#[test]
fn generation_rejects_assistant_before_user_millisecond() {
    let outcome = generation_outcome(
        ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
        ledger_message(
            ASSISTANT_MESSAGE_ID_AFTER,
            MessageRole::Assistant,
            SAME_MILLISECOND - 1,
        ),
    );
    assert!(
        !outcome.correlates_to_command(&generate_text_command()),
        "an assistant message committed before the user millisecond must not correlate"
    );
}

#[test]
fn generation_rejects_unprovable_same_millisecond_order() {
    let outcome = generation_outcome(
        ledger_message(USER_MESSAGE_ID, MessageRole::User, SAME_MILLISECOND),
        ledger_message(
            ASSISTANT_MESSAGE_ID_BEFORE,
            MessageRole::Assistant,
            SAME_MILLISECOND,
        ),
    );
    assert!(
        !outcome.correlates_to_command(&generate_text_command()),
        "a same-millisecond assistant id preceding the user id proves no valid \
         generation order and must not correlate"
    );
}

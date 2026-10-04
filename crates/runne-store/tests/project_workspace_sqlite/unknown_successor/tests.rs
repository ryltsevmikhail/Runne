use super::super::support::*;
use super::fixture::{
    running, running_with_remote_id, running_without_provider_admission, runtime_authority,
};
use runne_application::ports::{ApplicationCommandContext, ConversationRepository, EventStore};

mod successor_support;
pub(super) use successor_support::Resolver;
use successor_support::{create_successor, start_successor_attempt, verify_successor};

#[test]
fn populated_running_unknown_creates_successor_and_reopens() {
    verify_successor(running("unknown-successor-running", 0x71), 0x75, false);
}

#[test]
fn populated_cancelling_unknown_creates_successor_and_reopens() {
    verify_successor(running("unknown-successor-cancelling", 0x81), 0x85, true);
}

#[test]
fn operation24_successor_can_become_predecessor_again_and_reopens() {
    let first = running("unknown-successor-chain", 0x91);
    let first_successor = create_successor(&first, 0x96, first.version);
    let second_predecessor = start_successor_attempt(first, first_successor, 0x97);
    let second_successor = create_successor(&second_predecessor, 0x9b, second_predecessor.version);
    let reopened = crate::validated_reopen::reopen_store(
        second_predecessor.database.file.path(),
        second_predecessor.database.identity,
        runtime_authority(),
        guard(),
    )
    .unwrap();
    for taskrun_id in [second_predecessor.taskrun_id, second_successor] {
        assert!(reopened.load_task_run(taskrun_id).is_ok());
    }
}

pub(super) fn context(tail: u8, key_value: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command(tail),
        idempotency_key: key(key_value),
        principal_id: runne_application::ports::PrincipalId("principal-1".into()),
        actor: runne_domain::event::Actor::new("unknown-successor-test").unwrap(),
    }
}

mod remote_cancel_closure;
#[path = "tests/remote_effects_composite.rs"]
mod remote_effects_composite;
mod source1_effects;

#[path = "tests/no_admission.rs"]
mod no_admission;
mod remote_terminal;
mod remote_terminal_non_output;
mod remote_terminal_non_output_handover;

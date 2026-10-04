use super::output_helpers::{
    OUTPUT, assert_output_applied, assert_pending_output, completed_output_fixture,
    read_after_reopen,
};
use super::output_history::stream_history;
use super::output_ledger::{
    accounting_snapshot, application_cardinality, assert_ack_state, assert_reservations_settled,
    reservation_snapshot,
};
use super::output_occupation::{assert_active_occupation, assert_released_occupation, occupation};
use super::output_workflow::{
    assert_assistant_output, assert_running_without_assistant, assert_taskrun_succeeded,
};
use super::support::read;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::ProviderExecutionStore;
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderTerminalOutboxApplication,
};
use std::sync::Arc;

#[test]
fn completed_source_remains_pending_output_after_validated_reopen() {
    let prepared = completed_output_fixture("remote-effects-pending-reopen", 0xd6);
    let before = read(&prepared);
    assert_pending_output(&prepared, &before);
    assert_running_without_assistant(&prepared);
    assert_active_occupation(&prepared);

    let reopened = read_after_reopen(&prepared);
    assert_pending_output(&prepared, &reopened);
    assert_running_without_assistant(&prepared);
    assert_active_occupation(&prepared);
}

#[test]
fn exact_output_application_and_ack_replay_keep_one_terminal_effect() {
    let prepared = completed_output_fixture("remote-effects-output-ack", 0xd7);
    let pending_before_apply = read(&prepared);
    assert_pending_output(&prepared, &pending_before_apply);
    assert_running_without_assistant(&prepared);
    assert_active_occupation(&prepared);

    let pending = prepared
        .fixture
        .execution
        .pending_terminal_outbox()
        .unwrap();
    assert_eq!(pending.len(), 1);
    let authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard: Arc<dyn ProhibitedContentPort> = super::super::guard();
    let text = Arc::new(ConversationTextService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority,
        guard,
    ));
    let application =
        ConversationProviderTerminalApplication::new(prepared.fixture.database.store.clone(), text);
    let receipt = ProviderTerminalOutboxApplication::complete_provider_terminal(
        &application,
        &pending[0],
        OUTPUT.as_bytes(),
    )
    .unwrap();
    assert_ne!(receipt, [0; 32]);
    prepared
        .fixture
        .execution
        .acknowledge_terminal_outbox(pending[0].outbox_id, receipt)
        .unwrap();
    assert_taskrun_succeeded(&prepared);
    assert_assistant_output(&prepared);
    assert_released_occupation(&prepared);
    assert_ack_state(&prepared);
    assert_reservations_settled(&prepared);

    let applied = read(&prepared);
    assert_output_applied(&prepared, &applied);
    let after_first_apply = application_cardinality(&prepared);
    assert_eq!(after_first_apply, (1, 1, 1, 1, 2));
    let history_after_first_apply = stream_history(&prepared);
    let accounting_after_first_apply = accounting_snapshot(&prepared);
    let reserves_after_first_apply = reservation_snapshot(&prepared);
    let occupation_after_first_apply = occupation(&prepared);
    assert_eq!(
        ProviderTerminalOutboxApplication::complete_provider_terminal(
            &application,
            &pending[0],
            OUTPUT.as_bytes(),
        )
        .unwrap(),
        receipt,
        "replayed application returns the original receipt"
    );
    prepared
        .fixture
        .execution
        .acknowledge_terminal_outbox(pending[0].outbox_id, receipt)
        .unwrap();
    assert_eq!(application_cardinality(&prepared), after_first_apply);
    assert_eq!(accounting_snapshot(&prepared), accounting_after_first_apply);
    assert_eq!(stream_history(&prepared), history_after_first_apply);
    assert_eq!(reservation_snapshot(&prepared), reserves_after_first_apply);
    assert_eq!(occupation(&prepared), occupation_after_first_apply);
    assert_taskrun_succeeded(&prepared);
    assert_assistant_output(&prepared);
    assert_released_occupation(&prepared);
    assert_ack_state(&prepared);
    assert_reservations_settled(&prepared);

    let reopened = read_after_reopen(&prepared);
    assert_output_applied(&prepared, &reopened);
}

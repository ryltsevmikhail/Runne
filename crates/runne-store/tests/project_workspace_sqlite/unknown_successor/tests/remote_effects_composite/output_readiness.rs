use super::output_helpers::{completed_output_fixture, read_after_reopen};
use super::support::Prepared;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::ProviderExecutionStore;
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderTerminalOutboxApplication,
};
use std::sync::Arc;

#[test]
fn late_known_output_preserves_unknown_dispatch_state_through_ack_and_reopen() {
    let prepared = completed_output_fixture("remote-effects-late-known-d6", 0x96);
    assert_eq!(dispatch_state(&prepared), (6, 2, 1));
    let pending = read_after_reopen(&prepared);
    assert_eq!(
        pending.remote.unwrap().local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::Pending
    );

    let outbox = prepared
        .fixture
        .execution
        .pending_terminal_outbox()
        .unwrap();
    assert_eq!(outbox.len(), 1);
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
        &outbox[0],
        super::output_helpers::OUTPUT.as_bytes(),
    )
    .unwrap();
    prepared
        .fixture
        .execution
        .acknowledge_terminal_outbox(outbox[0].outbox_id, receipt)
        .unwrap();

    assert_eq!(dispatch_state(&prepared), (6, 4, 2));
    assert_eq!(
        read_after_reopen(&prepared)
            .remote
            .unwrap()
            .local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::OutputApplied
    );
}

#[test]
fn missing_original_terminal_disposition_fails_validated_reopen() {
    let prepared =
        super::output_states::completed_before_unknown("remote-effects-missing-disposition", 0x97);
    assert_eq!(dispatch_state(&prepared), (4, 2, 1));
    let _ = read_after_reopen(&prepared);

    let connection = prepared.fixture.database.connection();
    let original_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger'
             AND name='provider_terminal_dispositions_no_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER provider_terminal_dispositions_no_delete")
        .unwrap();
    connection
        .execute(
            "DELETE FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    connection.execute_batch(&original_trigger).unwrap();
    let restored_trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger'
             AND name='provider_terminal_dispositions_no_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(restored_trigger, original_trigger);

    let reopen = crate::validated_reopen::reopen_store(
        prepared.fixture.database.file.path(),
        prepared.fixture.database.identity,
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
        super::super::guard(),
    );
    assert!(
        reopen.is_err(),
        "the missing disposition must fail readiness"
    );
}

fn dispatch_state(prepared: &Prepared) -> (i64, i64, i64) {
    prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT d.state,s.settlement_state,o.state
             FROM provider_dispatch_attempts d
             JOIN provider_remote_terminal_settlements s ON s.dispatch_attempt_id=d.attempt_id
             JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=d.attempt_id
             WHERE d.attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

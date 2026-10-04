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
fn source_readiness_rejects_unmatched_admission_and_original_reservation() {
    let prepared = pending("remote-v59-admission-tamper", 0x98);
    let connection = prepared.fixture.database.connection();
    connection
        .execute(
            "UPDATE provider_execution_admissions SET principal_id='other-principal'
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-reservation-tamper", 0x99);
    let connection = prepared.fixture.database.connection();
    connection
        .execute(
            "UPDATE provider_budget_reservations SET amount=amount+1
             WHERE reservation_id=(SELECT token_reservation_id
                 FROM provider_execution_admissions WHERE dispatch_attempt_id=?1)",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-cost-reservation-tamper", 0x9a);
    prepared
        .fixture
        .database
        .connection()
        .execute(
            "UPDATE provider_budget_reservations SET amount=amount+1
             WHERE reservation_id=(SELECT cost_reservation_id
                 FROM provider_execution_admissions WHERE dispatch_attempt_id=?1)",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);
}

#[test]
fn source_readiness_rejects_changed_original_claim_and_begin_pins() {
    let prepared = pending("remote-v59-claim-tamper", 0x9b);
    let connection = prepared.fixture.database.connection();
    let trigger = trigger_sql(&connection, "taskrun_claim_receipts_immutable");
    connection
        .execute_batch("DROP TRIGGER taskrun_claim_receipts_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE taskrun_claim_receipts SET new_version=new_version+1
             WHERE taskrun_id=?1 AND attempt_id=?2",
            rusqlite::params![
                prepared.fixture.taskrun_id.as_bytes(),
                prepared.fixture.claim_identity.attempt_id.as_bytes()
            ],
        )
        .unwrap();
    connection.execute_batch(&trigger).unwrap();
    assert_eq!(
        trigger_sql(&connection, "taskrun_claim_receipts_immutable"),
        trigger
    );
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-begin-pin-tamper", 0x9c);
    let connection = prepared.fixture.database.connection();
    let identity_trigger = trigger_sql(
        &connection,
        "provider_remote_terminal_settlements_identity_immutable",
    );
    let state_transition_trigger = trigger_sql(
        &connection,
        "provider_remote_terminal_settlements_state_transition",
    );
    connection
        .execute_batch(
            "DROP TRIGGER provider_remote_terminal_settlements_identity_immutable;
             DROP TRIGGER provider_remote_terminal_settlements_state_transition",
        )
        .unwrap();
    let changed = connection
        .execute(
            "UPDATE provider_remote_terminal_settlements SET writer_owner_principal='forged-owner'
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(changed, 1, "the original writer pin was changed");
    let forged_owner: String = connection
        .query_row(
            "SELECT writer_owner_principal FROM provider_remote_terminal_settlements
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(forged_owner, "forged-owner");
    connection.execute_batch(&identity_trigger).unwrap();
    connection.execute_batch(&state_transition_trigger).unwrap();
    assert_eq!(
        trigger_sql(
            &connection,
            "provider_remote_terminal_settlements_identity_immutable"
        ),
        identity_trigger
    );
    assert_eq!(
        trigger_sql(
            &connection,
            "provider_remote_terminal_settlements_state_transition"
        ),
        state_transition_trigger
    );
    assert_reopen_rejected(&prepared);
}

#[test]
fn source_readiness_rejects_request_ledger_and_pending_outbox_tampering() {
    let prepared = pending("remote-v59-request-tamper", 0x9d);
    let connection = prepared.fixture.database.connection();
    let trigger = trigger_sql(&connection, "provider_remote_request_intents_immutable");
    connection
        .execute_batch("DROP TRIGGER provider_remote_request_intents_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE provider_remote_request_intents SET request_digest=?1
             WHERE dispatch_attempt_id=?2",
            rusqlite::params![
                [0x55_u8; 32].as_slice(),
                prepared.attempt.as_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(connection.changes(), 1);
    let changed_digest: Vec<u8> = connection
        .query_row(
            "SELECT request_digest FROM provider_remote_request_intents
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(changed_digest, vec![0x55; 32]);
    connection.execute_batch(&trigger).unwrap();
    assert_eq!(
        trigger_sql(&connection, "provider_remote_request_intents_immutable"),
        trigger
    );
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-ledger-tamper", 0x9e);
    prepared
        .fixture
        .database
        .connection()
        .execute(
            "UPDATE provider_accounting_settlements SET input_tokens=input_tokens+1
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);

    let prepared = pending("remote-v59-outbox-tamper", 0x91);
    prepared
        .fixture
        .database
        .connection()
        .execute(
            "UPDATE provider_terminal_outbox SET plaintext_digest=zeroblob(32)
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);
}

#[test]
fn source_readiness_rejects_tampered_acknowledgement_receipt() {
    let prepared = pending("remote-v59-ack-tamper", 0x92);
    acknowledge(&prepared);
    let connection = prepared.fixture.database.connection();
    connection
        .execute(
            "UPDATE provider_terminal_outbox SET receipt_digest=zeroblob(32)
             WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
        )
        .unwrap();
    assert_reopen_rejected(&prepared);
}

pub(super) fn pending(name: &str, tail: u8) -> Prepared {
    let prepared = super::output_states::completed_before_unknown(name, tail);
    let _ = super::output_helpers::read_after_reopen(&prepared);
    prepared
}

fn acknowledge(prepared: &Prepared) {
    let outbox = prepared
        .fixture
        .execution
        .pending_terminal_outbox()
        .unwrap();
    assert_eq!(outbox.len(), 1);
    let guard: Arc<dyn ProhibitedContentPort> = super::super::guard();
    let text = Arc::new(ConversationTextService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
        guard,
    ));
    let application =
        ConversationProviderTerminalApplication::new(prepared.fixture.database.store.clone(), text);
    let receipt = ProviderTerminalOutboxApplication::complete_provider_terminal(
        &application,
        &outbox[0],
        b"strict v59 output",
    )
    .unwrap();
    prepared
        .fixture
        .execution
        .acknowledge_terminal_outbox(outbox[0].outbox_id, receipt)
        .unwrap();
}

pub(super) fn assert_reopen_rejected(prepared: &Prepared) {
    assert!(
        crate::validated_reopen::reopen_store(
            prepared.fixture.database.file.path(),
            prepared.fixture.database.identity,
            RuntimeAuthorityId("01010101010101010101010101010101".into()),
            super::super::guard(),
        )
        .is_err(),
        "tampered original source evidence must fail validated reopen"
    );
}

pub(super) fn trigger_sql(connection: &rusqlite::Connection, name: &str) -> String {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}

use self::producer::conversation_id;
use super::output_helpers::read_after_reopen;
use super::support::{Prepared, Price};
use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, PreparedTaskRunProviderRequest, TaskRunProviderBindingPort,
};
use runne_application::provider::{ProviderExecutionStore, ProviderRemoteRecoveryStore};
use runne_application::service::TaskRunService;
use runne_provider::{
    ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId, ProviderRecoveryBinding,
    ProviderRemoteCheck, ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderUsage, RemoteResponseId,
};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderRemoteTerminalSourceOutcome,
    ProviderTerminalOutboxApplication, RuntimeProviderRemoteIdentityCommitter,
};
use std::sync::Arc;

#[test]
fn current_output_readiness_accepts_real_dispatch_states_four_and_five() {
    let prepared = completed_before_unknown("remote-effects-v59-d4-d5", 0x91);
    assert_dispatch_source(&prepared, 4, 2, 1);
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
    let authority =
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard: Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> =
        super::super::guard();
    let text = Arc::new(
        runne_application::conversation_text_service::ConversationTextService::new(
            prepared.fixture.database.store.clone(),
            prepared.fixture.database.store.clone(),
            authority,
            guard,
        ),
    );
    let application =
        ConversationProviderTerminalApplication::new(prepared.fixture.database.store.clone(), text);
    let receipt = ProviderTerminalOutboxApplication::complete_provider_terminal(
        &application,
        &outbox[0],
        b"strict v59 output",
    )
    .unwrap();
    let applied_before_ack = read_after_reopen(&prepared);
    assert_eq!(
        applied_before_ack.remote.unwrap().local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::Pending,
        "a committed local application must remain reopenable before its outbox ACK"
    );
    prepared
        .fixture
        .execution
        .acknowledge_terminal_outbox(outbox[0].outbox_id, receipt)
        .unwrap();

    assert_dispatch_source(&prepared, 5, 4, 2);
    let closed = read_after_reopen(&prepared);
    assert_eq!(
        closed.remote.unwrap().local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::OutputApplied
    );
}

#[test]
fn writer_transfer_keeps_pending_source_reopenable_and_acknowledges_audit_only() {
    let prepared = completed_before_unknown("remote-effects-v59-writer-transfer", 0x92);
    let conversation_id = conversation_id(&prepared.fixture);
    let prior_fence = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    prepared
        .fixture
        .database
        .store
        .take_control_conversation_writer_lease(
            conversation_id.as_bytes(),
            "successor-writer",
            u64::try_from(prior_fence).unwrap(),
        )
        .unwrap();
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
    let authority =
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into());
    let guard: Arc<dyn runne_application::prohibited_content::ProhibitedContentPort> =
        super::super::guard();
    let text = Arc::new(
        runne_application::conversation_text_service::ConversationTextService::new(
            prepared.fixture.database.store.clone(),
            prepared.fixture.database.store.clone(),
            authority,
            guard,
        ),
    );
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
    let closed = read_after_reopen(&prepared);
    assert_eq!(
        closed.remote.unwrap().local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::AuditOnly
    );
    let (source_state, dispatch_state): (i64, i64) = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT s.settlement_state,d.state FROM provider_remote_terminal_settlements s
             JOIN provider_dispatch_attempts d ON d.attempt_id=s.dispatch_attempt_id
             WHERE s.dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((source_state, dispatch_state), (4, 5));
}

#[test]
fn accepted_cancellation_keeps_pending_source_reopenable_before_audit_ack() {
    let prepared = completed_before_unknown("remote-effects-v59-cancel-pending", 0x93);
    let authority =
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into());
    TaskRunService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority,
    )
    .cancel_task_run(
        &super::super::context(0xe4, "v59-cancel-pending"),
        CancelTaskRunInput {
            taskrun_id: prepared.fixture.taskrun_id,
            expected_version: 4,
        },
    )
    .unwrap();

    let pending = read_after_reopen(&prepared);
    let remote = pending.remote.unwrap();
    assert_eq!(
        remote.local_disposition,
        runne_application::provider::ProviderRemoteLocalDisposition::Pending
    );
    assert_eq!(
        pending.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        pending.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::Unconfirmed
    );
}

#[path = "output_states/producer.rs"]
mod producer;
pub(super) use producer::{assert_dispatch_source, completed_before_unknown};

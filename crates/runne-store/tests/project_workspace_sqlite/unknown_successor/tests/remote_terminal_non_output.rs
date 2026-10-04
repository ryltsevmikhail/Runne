use super::*;
use runne_application::ports::EventStore;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_provider::{
    ProviderPricedUsage, ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderTerminalPricing, ProviderTerminalPricingError,
    ProviderUsage, RemoteResponseId,
};

type RemoteTerminalNonOutputState = (
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    i64,
    i64,
    i64,
);
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderRemoteNoOutputApplication,
    ProviderRemoteTerminalSourceOutcome, RuntimeProviderRemoteIdentityCommitter,
};
use std::sync::Arc;

struct Price;

impl ProviderTerminalPricing for Price {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        ProviderPricedUsage::new(10, "USD".into())
    }
}

#[test]
fn failed_remote_terminal_settles_actual_usage_without_output_outbox() {
    let fixture = running_with_remote_id(
        "remote-failed-terminal-finance",
        0xb4,
        "resp_failed_finance",
    );
    let connection = fixture.database.connection();
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let attempt = runne_provider::DispatchAttemptId::from_bytes(
        bytes.try_into().expect("dispatch attempt id is 16 bytes"),
    );
    let source_count: i64 = fixture.database.connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        source_count, 0,
        "request identity alone is not a terminal source"
    );
    let submitted = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let conversation_id = submitted
        .events
        .iter()
        .find_map(|event| match event.payload() {
            runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .expect("submitted TaskRun has immutable conversation origin");
    let snapshot = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let binding = snapshot.request.binding.clone();
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let keyring = Arc::new(super::super::effect::Keyring);
    let committer =
        RuntimeProviderRemoteIdentityCommitter::new(keyring, Arc::clone(&fixture.execution));
    let response_id = RemoteResponseId::new("resp_failed_finance").unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let status = ProviderRemoteResponseStatus::Failed {
        code: Some("provider_failed".into()),
        usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
    };
    let terminal =
        ProviderRemoteTerminalArtifact::new(response_id.clone(), status.clone(), None).unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(terminal),
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &Price)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::AuditOnly,
    );
    assert_eq!(
        fixture
            .execution
            .scan_remote_attempts(None, 16)
            .unwrap()
            .attempts,
        vec![attempt],
        "the factual non-output source remains discoverable until application"
    );
    let text_service = Arc::new(
        runne_application::conversation_text_service::ConversationTextService::new(
            fixture.database.store.clone(),
            fixture.database.store.clone(),
            runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into()),
            super::guard(),
        ),
    );
    let application =
        ConversationProviderTerminalApplication::new(fixture.database.store.clone(), text_service);
    assert!(
        application
            .apply_remote_terminal_without_output(attempt)
            .unwrap()
    );
    assert!(
        !application
            .apply_remote_terminal_without_output(attempt)
            .unwrap()
    );
    let connection = fixture.database.connection();
    let (source_state, input, charge, source_digest, accounting, disposition, outboxes, reserve):
        RemoteTerminalNonOutputState = connection
        .query_row(
            "SELECT s.settlement_state,s.input_tokens,s.charge_micros,s.settlement_digest,
                (SELECT COUNT(*) FROM provider_accounting_settlements a WHERE a.dispatch_attempt_id=s.dispatch_attempt_id),
                (SELECT disposition FROM provider_terminal_dispositions d WHERE d.dispatch_attempt_id=s.dispatch_attempt_id),
                (SELECT COUNT(*) FROM provider_terminal_outbox o WHERE o.dispatch_attempt_id=s.dispatch_attempt_id),
                (SELECT COUNT(*) FROM provider_budget_reservations b WHERE b.provider_idempotency_key=(SELECT provider_idempotency_key FROM provider_dispatch_attempts p WHERE p.attempt_id=s.dispatch_attempt_id) AND b.state=1)
             FROM provider_remote_terminal_settlements s WHERE s.dispatch_attempt_id=?1",
            [attempt.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (source_state, input, charge, source_digest),
        (3, Some(3), None, None)
    );
    assert_eq!((accounting, disposition, outboxes, reserve), (1, 2, 0, 0));
    let reservation: (Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT SUM(CASE WHEN dimension=1 THEN settled_amount END),
                    SUM(CASE WHEN dimension=2 THEN settled_amount END)
             FROM provider_budget_reservations
             WHERE provider_idempotency_key=(SELECT provider_idempotency_key FROM provider_dispatch_attempts WHERE attempt_id=?1)",
            [attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(reservation, (Some(7), Some(10)));
    assert!(
        fixture
            .database
            .store
            .load_conversation(conversation_id)
            .unwrap()
            .events
            .iter()
            .all(|event| !matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
                    taskrun_id, ..
                } if *taskrun_id == fixture.taskrun_id
            ))
    );
    let taskrun = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&taskrun.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Failed
    );
    assert!(
        fixture
            .execution
            .scan_remote_attempts(None, 16)
            .unwrap()
            .attempts
            .is_empty()
    );
    let authority =
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into());
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        authority.clone(),
        super::guard(),
    )
    .unwrap();
    let reopened_text = Arc::new(
        runne_application::conversation_text_service::ConversationTextService::new(
            reopened.clone(),
            reopened.clone(),
            authority,
            super::guard(),
        ),
    );
    let reopened_application =
        ConversationProviderTerminalApplication::new(reopened, reopened_text);
    assert!(
        !reopened_application
            .apply_remote_terminal_without_output(attempt)
            .unwrap(),
        "the exact v61 application receipt suppresses duplicate local effects after reopen"
    );
}

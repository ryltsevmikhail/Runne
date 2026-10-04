use super::super::effect::Keyring;
use super::super::fixture::running_with_remote_id;
use runne_application::commands::{ConversationTextCompletion, FinishConversationTextInput};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService, ConversationTextServiceError,
};
use runne_application::ports::{EventStore, RuntimeAuthorityId};
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_domain::conversation::GenerationFailureReason;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_provider::{
    ProviderPricedUsage, ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderTerminalPricing, ProviderTerminalPricingError,
    ProviderUsage, RemoteResponseId,
};

type RemoteTerminalSourceState = (
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    i64,
);
use runne_runtime::provider_execution::{
    ProviderTerminalConversationResolver, RuntimeProviderRemoteIdentityCommitter,
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
fn stale_non_output_command_cannot_close_generation_after_writer_handover() {
    let fixture = running_with_remote_id("non-output-writer-handover", 0xa9, "resp_handover");
    let snapshot = fixture
        .execution
        .load_remote_attempt_history(fixture.taskrun_id, fixture.claim_identity.attempt_id)
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
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(Keyring),
        Arc::clone(&fixture.execution),
    );
    let response_id = RemoteResponseId::new("resp_handover").unwrap();
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
        usage: Some(ProviderUsage::new(1, 1, 0, 0).unwrap()),
    };
    let artifact =
        ProviderRemoteTerminalArtifact::new(response_id.clone(), status.clone(), None).unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(artifact),
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    committer
        .commit_authenticated_remote_terminal_source(recovery, &Price)
        .unwrap();

    let recovered = fixture
        .database
        .store
        .resolve_remote_terminal_without_output(binding.dispatch_attempt_id)
        .unwrap()
        .unwrap();
    let conversation_id = recovered.original.conversation_id;
    let before_version = fixture.database.connection().query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=2 AND aggregate_id=?1",
        [conversation_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    ).unwrap();
    let prior_fence = fixture
        .database
        .connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    let task_history_before = format!(
        "{:?}",
        fixture
            .database
            .store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .events
    );
    let reservations_before = reservation_snapshot(&fixture, binding.dispatch_attempt_id);
    let source_before: RemoteTerminalSourceState =
        fixture.database.connection().query_row(
            "SELECT s.settlement_state,s.input_tokens,s.output_tokens,s.charge_micros,s.settlement_digest,
                    (SELECT COUNT(*) FROM provider_accounting_settlements a WHERE a.dispatch_attempt_id=s.dispatch_attempt_id),
                    (SELECT COUNT(*) FROM provider_terminal_outbox o WHERE o.dispatch_attempt_id=s.dispatch_attempt_id)
             FROM provider_remote_terminal_settlements s WHERE s.dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).unwrap();
    fixture
        .database
        .store
        .take_control_conversation_writer_lease(
            conversation_id.as_bytes(),
            "successor-writer",
            u64::try_from(prior_fence).unwrap(),
        )
        .unwrap();

    let service = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        RuntimeAuthorityId("01010101010101010101010101010101".into()),
        super::guard(),
    );
    let result = service.finish_text(
        &recovered.context,
        FinishConversationTextInput {
            original: recovered.original,
            started: recovered.started,
            completion: ConversationTextCompletion::Rejected {
                reason: GenerationFailureReason::ProviderExecutionFailed,
            },
        },
    );
    let task = TaskRun::replay(
        &fixture
            .database
            .store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .events,
    )
    .unwrap();
    assert_eq!(task.state(), TaskRunState::Running);
    let task_history_after = format!(
        "{:?}",
        fixture
            .database
            .store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .events
    );
    let connection = fixture.database.connection();
    let after_version: i64 = connection.query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=2 AND aggregate_id=?1",
        [conversation_id.as_bytes().as_slice()],
        |row| row.get(0),
    ).unwrap();
    let applications: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_terminal_applications WHERE dispatch_attempt_id=?1",
        [binding.dispatch_attempt_id.as_bytes().as_slice()],
        |row| row.get(0),
    ).unwrap();
    let source_after: RemoteTerminalSourceState =
        connection.query_row(
            "SELECT s.settlement_state,s.input_tokens,s.output_tokens,s.charge_micros,s.settlement_digest,
                    (SELECT COUNT(*) FROM provider_accounting_settlements a WHERE a.dispatch_attempt_id=s.dispatch_attempt_id),
                    (SELECT COUNT(*) FROM provider_terminal_outbox o WHERE o.dispatch_attempt_id=s.dispatch_attempt_id)
             FROM provider_remote_terminal_settlements s WHERE s.dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).unwrap();
    assert_eq!(after_version, before_version);
    assert_eq!(applications, 0);
    assert_eq!(
        source_after, source_before,
        "stale application cannot change accounting or delivery facts"
    );
    assert_eq!(
        task_history_after, task_history_before,
        "stale application cannot append TaskRun history"
    );
    assert_eq!(
        reservation_snapshot(&fixture, binding.dispatch_attempt_id),
        reservations_before,
        "stale application cannot settle or release the original reservation"
    );
    assert!(
        matches!(&result, Err(ConversationTextServiceError::WriterFenced)),
        "a transfer after preparation is a normal writer fence: {result:?}"
    );
}

fn reservation_snapshot(
    fixture: &super::super::fixture::Fixture,
    dispatch_attempt_id: runne_provider::DispatchAttemptId,
) -> Vec<(i64, i64, Option<i64>, Option<i64>)> {
    fixture
        .database
        .connection()
        .prepare(
            "SELECT b.dimension,b.state,b.settled_amount,b.released_at
             FROM provider_budget_reservations b
             JOIN provider_dispatch_attempts p
               ON p.provider_idempotency_key=b.provider_idempotency_key
             WHERE p.attempt_id=?1 ORDER BY b.dimension",
        )
        .unwrap()
        .query_map([dispatch_attempt_id.as_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

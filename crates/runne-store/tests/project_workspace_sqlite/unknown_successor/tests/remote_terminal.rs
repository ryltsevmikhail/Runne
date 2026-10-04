use super::*;
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::provider::ProviderExecutionStore;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_domain::message::MessageText;
use runne_provider::{
    ProviderPricedUsage, ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderTerminalPricing, ProviderTerminalPricingError,
    ProviderUsage, RemoteResponseId,
};
use runne_runtime::provider_execution::{
    ProviderRemoteTerminalSourceOutcome, RuntimeProviderRemoteIdentityCommitter,
};
use sha2::Digest as _;
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
fn authenticated_remote_terminal_is_pinned_and_settled_from_running_generation() {
    let fixture = running_with_remote_id(
        "remote-terminal-source-positive",
        0xa1,
        "resp_source_positive",
    );
    let connection = fixture.database.connection();
    let attempt: Vec<u8> = connection
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let attempt = runne_provider::DispatchAttemptId::from_bytes(
        attempt.try_into().expect("dispatch attempt id is 16 bytes"),
    );
    drop(connection);
    let snapshot = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let binding = snapshot.request.binding.clone();
    assert!(snapshot.terminal.is_none());
    let response = snapshot
        .response
        .as_ref()
        .expect("durable early response ID");
    assert_eq!(response.binding, binding);
    let expected_id_digest: [u8; 32] = sha2::Sha256::digest(b"resp_source_positive").into();
    assert_eq!(
        response.encrypted_response_id.plaintext_digest(),
        &expected_id_digest
    );
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let keyring = Arc::new(super::super::effect::Keyring);
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&keyring),
        Arc::clone(&fixture.execution),
    );
    let response_id = RemoteResponseId::new("resp_source_positive").unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let status = ProviderRemoteResponseStatus::Completed {
        usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
    };
    let terminal = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        Some("recovered exact output".into()),
    )
    .unwrap();
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
    let terminal_snapshot = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let artifact_digest = terminal_snapshot
        .terminal
        .as_ref()
        .unwrap()
        .encrypted_artifact
        .plaintext_digest();

    let result = committer
        .commit_authenticated_remote_terminal_source(recovery, &Price)
        .unwrap();
    assert_eq!(
        result,
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let pending_scan = fixture.execution.scan_remote_attempts(None, 8).unwrap();
    assert_eq!(pending_scan.attempts, vec![attempt]);
    assert_eq!(
        fixture
            .execution
            .find_remote_attempt(binding.taskrun_id, binding.taskrun_attempt_id)
            .unwrap(),
        Some(attempt),
        "a committed artifact remains discoverable until its local receipt is acknowledged"
    );
    let connection = fixture.database.connection();
    let source: (i64, Option<i64>, Option<i64>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT settlement_state,input_tokens,charge_micros,begin_command_id,conversation_id
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [attempt.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!((source.0, source.1, source.2), (2, Some(3), Some(10)));
    let outbox: (i64, i64, Vec<u8>) = connection
        .query_row(
            "SELECT terminal_sequence,state,plaintext_digest FROM provider_terminal_outbox
             WHERE dispatch_attempt_id=?1",
            [attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(outbox.0, 0);
    assert_eq!(outbox.1, 1);
    assert_eq!(outbox.2.as_slice(), artifact_digest.as_slice());
    drop(connection);

    let replay = committer
        .commit_authenticated_remote_terminal_source(recovery, &Price)
        .unwrap();
    assert_eq!(
        replay,
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let connection = fixture.database.connection();
    let counts: (i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_remote_terminal_settlements),
                    (SELECT COUNT(*) FROM provider_accounting_settlements),
                    (SELECT COUNT(*) FROM provider_terminal_outbox)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1, 1));
    drop(connection);

    let begin_command = runne_domain::id::CommandId::from_bytes(
        source
            .3
            .as_slice()
            .try_into()
            .expect("begin command id is 16 bytes"),
    );
    let conversation_id = runne_domain::id::ConversationId::from_bytes(
        source
            .4
            .as_slice()
            .try_into()
            .expect("conversation id is 16 bytes"),
    );
    let begin_key = super::key("unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(begin_command, &begin_key)
        .unwrap();
    let service = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into()),
        guard(),
    );
    let finish_context = super::context(0xa3, "unknown-successor-generation");
    let finish = |output: &str| FinishConversationTextInput {
        original: BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("successor fixture request").unwrap(),
        },
        started: started.clone(),
        completion: ConversationTextCompletion::AssistantText(
            MessageText::new(output.to_owned()).unwrap(),
        ),
    };
    assert!(
        service
            .finish_text(&finish_context, finish("mismatched artifact text"))
            .is_err()
    );
    service
        .finish_text(&finish_context, finish("recovered exact output"))
        .unwrap();
    let pending = fixture.execution.pending_terminal_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    let application =
        runne_runtime::provider_execution::ConversationProviderTerminalApplication::new(
            fixture.database.store.clone(),
            Arc::new(service),
        );
    let receipt = runne_runtime::provider_execution::ProviderTerminalOutboxApplication::complete_provider_terminal(
        &application, &pending[0], b"recovered exact output",
    ).unwrap();
    assert!(
        fixture
            .execution
            .acknowledge_terminal_outbox(pending[0].outbox_id, [7; 32])
            .is_err()
    );
    fixture
        .execution
        .acknowledge_terminal_outbox(pending[0].outbox_id, receipt)
        .unwrap();
    assert!(
        fixture
            .execution
            .scan_remote_attempts(None, 8)
            .unwrap()
            .attempts
            .is_empty()
    );
    fixture
        .execution
        .acknowledge_terminal_outbox(pending[0].outbox_id, receipt)
        .unwrap();
    assert!(
        fixture
            .execution
            .pending_terminal_outbox()
            .unwrap()
            .is_empty()
    );

    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into()),
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .current_version,
        fixture.version + 1
    );
    let connection = fixture.database.connection();
    let state: (i64, i64) = connection.query_row(
        "SELECT settlement_state,(SELECT state FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1)
         FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
        [attempt.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(state, (4, 2));
    drop(connection);
}

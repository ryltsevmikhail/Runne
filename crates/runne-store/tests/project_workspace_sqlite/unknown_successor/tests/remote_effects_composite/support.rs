use super::super::*;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{ConversationRepository, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::{ProviderRemoteFactAuthenticator, ProviderRemoteRecoveryStore};
use runne_provider::{
    DispatchAttemptId, ProviderPricedUsage, ProviderRecoveryBinding, ProviderRecoveryOperation,
    ProviderRemoteCheck, ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderStreamEvent, ProviderTerminalPricing,
    ProviderTerminalPricingError, ProviderUsage, RemoteResponseId, ScannerTerminalDisposition,
};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderEventJournalContext,
    ProviderRemoteTerminalSourceOutcome, RuntimeProviderExecution,
    RuntimeProviderRemoteIdentityCommitter,
};
use runne_runtime::provider_redaction::{
    PreJournalProviderEvent, ProviderEventRedaction, ProviderRedactionError,
};
use std::sync::Arc;

pub(super) struct Price;

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

pub(super) type Fixture = super::super::super::fixture::Fixture;
type Keyring = super::super::super::effect::Keyring;
type Committer = RuntimeProviderRemoteIdentityCommitter<
    Keyring,
    runne_store::provider::SqliteProviderExecutionStore,
>;

struct NoopRedaction;

impl ProviderEventRedaction for NoopRedaction {
    fn scan_before_journal(
        &self,
        _: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<PreJournalProviderEvent, ProviderRedactionError> {
        Ok(PreJournalProviderEvent::Append(event.clone()))
    }

    fn terminal_disposition(
        &self,
        _: DispatchAttemptId,
    ) -> Result<Option<ScannerTerminalDisposition>, ProviderRedactionError> {
        Ok(None)
    }
}

pub(super) struct Prepared {
    pub fixture: Fixture,
    pub attempt: runne_provider::DispatchAttemptId,
    pub recovery: ProviderRecoveryBinding,
    pub committer: Arc<Committer>,
    pub artifact_digest: [u8; 32],
}

pub(super) fn prepare(
    name: &str,
    tail: u8,
    response: &str,
    status: ProviderRemoteResponseStatus,
    output: Option<&str>,
) -> Prepared {
    let fixture = running_with_remote_id(name, tail, response);
    let attempt = attempt(&fixture);
    let remote = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let binding = remote.request.binding.clone();
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let response_id = RemoteResponseId::new(response).unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let terminal = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        output.map(str::to_owned),
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
    let committer = Arc::new(RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(super::super::super::effect::Keyring),
        Arc::clone(&fixture.execution),
    ));
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    let artifact_digest = *fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap()
        .terminal
        .unwrap()
        .encrypted_artifact
        .plaintext_digest();
    Prepared {
        fixture,
        attempt,
        recovery,
        committer,
        artifact_digest,
    }
}

pub(super) fn commit(prepared: &Prepared) -> ProviderRemoteTerminalSourceOutcome {
    commit_with(prepared, &Price)
}

pub(super) fn commit_with(
    prepared: &Prepared,
    pricing: &impl ProviderTerminalPricing,
) -> ProviderRemoteTerminalSourceOutcome {
    prepared
        .committer
        .commit_authenticated_remote_terminal_source(prepared.recovery, pricing)
        .unwrap()
}

fn attempt(fixture: &Fixture) -> DispatchAttemptId {
    DispatchAttemptId::from_bytes(
        fixture
            .database
            .connection()
            .query_row(
                "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1",
                [fixture.taskrun_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

pub(super) fn has_assistant_output(
    fixture: &Fixture,
    conversation_id: runne_domain::id::ConversationId,
) -> bool {
    fixture
        .database
        .store
        .load_conversation(conversation_id)
        .unwrap()
        .events
        .iter()
        .any(|event| {
            matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
                    taskrun_id, ..
                } if *taskrun_id == fixture.taskrun_id
            )
        })
}

pub(super) fn read(prepared: &Prepared) -> runne_application::ports::TaskRunEffectsReadSnapshot {
    prepared
        .fixture
        .database
        .store
        .load_task_run_effects_with_remote_authenticator(
            prepared.fixture.taskrun_id,
            Some(prepared.committer.as_ref() as &dyn ProviderRemoteFactAuthenticator),
            Some(&super::super::Resolver),
        )
        .unwrap()
}

pub(super) fn assert_cancelled_source_is_audit_only(prepared: &Prepared) {
    let connection = prepared.fixture.database.connection();
    let (state, application_receipt): (i64, Option<Vec<u8>>) = connection
        .query_row(
            "SELECT settlement_state,application_receipt_digest
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, 3, "accepted cancellation retains the audit source");
    assert!(
        application_receipt.is_none(),
        "audit source has no application ACK"
    );
    let outbox_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outbox_count, 0, "pre-source cancellation creates no outbox");

    let accounting: (i64, i64, i64, i64, i64, String) = connection
        .query_row(
            "SELECT input_tokens,output_tokens,cached_input_tokens,
                    reasoning_output_tokens,charge_micros,currency
             FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(accounting, (3, 4, 0, 0, 10, "USD".into()));

    let (count, dimensions, settled): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(b.dimension),0),
                    COALESCE(SUM(CASE WHEN b.settled_amount IS NOT NULL
                                      AND b.released_at IS NOT NULL THEN 1 ELSE 0 END),0)
             FROM provider_budget_reservations b
             JOIN provider_dispatch_attempts p USING(provider_idempotency_key)
             WHERE p.attempt_id=?1 AND b.state=2",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((count, dimensions, settled), (2, 3, 2));
}

pub(super) fn apply_pending_cancellation(prepared: &Prepared, authority: &RuntimeAuthorityId) {
    let guard: Arc<dyn ProhibitedContentPort> = super::super::guard();
    let keyring = super::super::super::effect::Keyring;
    let runtime = RuntimeProviderExecution::new(
        &keyring,
        prepared.fixture.execution.as_ref(),
        &Price,
        guard.as_ref(),
        &NoopRedaction,
    );
    let text = ConversationTextService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority.clone(),
        Arc::clone(&guard),
    );
    let application = ConversationProviderTerminalApplication::new(
        prepared.fixture.database.store.clone(),
        Arc::new(text),
    );
    assert!(
        runtime
            .apply_terminal_cancellation_output_for_attempt(prepared.attempt, &application)
            .unwrap()
    );
}

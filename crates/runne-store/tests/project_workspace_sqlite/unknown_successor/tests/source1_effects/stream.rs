use super::super::super::fixture::Fixture;
use runne_application::ports::EventStore;
use runne_provider::{
    DispatchError, DispatchRequest, ModelRef, PrepareError, PreparedRequest, ProviderCall,
    ProviderFuture, ProviderPort, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_store::provider::{
    CredentialDispatchAuthority, PreparedProviderRecord, ProviderCoordinatorOutcome,
    ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    SqliteProviderDispatchCoordinator,
};

struct Ready(DispatchRequest);

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

struct StreamEffect;

impl ProviderEffectPort for StreamEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: runne_store::provider::CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::AttemptConflict)?;
            Ok(ProviderStreamId::from_bytes(
                *ready.0.attempt_id().as_bytes(),
            ))
        })
    }
}

struct Adapter;

impl ProviderPort for Adapter {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call).map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
            .map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            Ok(ProviderStreamId::from_bytes(
                *request.attempt_id().as_bytes(),
            ))
        })
    }

    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { Err(StreamError::Closed) })
    }

    fn cancel(
        &self,
        _: runne_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<runne_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(runne_provider::CancelDisposition::Requested) })
    }

    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

pub(super) fn dispatch(fixture: &mut Fixture, requested_input_tokens: u64) {
    let dispatch = crate::validated_reopen::open_provider_dispatch(
        fixture.database.file.path(),
        fixture.database.identity,
    )
    .unwrap();
    let provider_id = runne_provider::ProviderId::new("fixture-provider").unwrap();
    let call = ProviderCall::new(
        runne_provider::ProviderCallId::from_bytes(*fixture.taskrun_id.as_bytes()),
        ModelRef::new(provider_id, "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    dispatch
        .persist_prepared(
            &fixture.launch,
            &PreparedProviderRecord {
                call_id: call.call_id(),
                call_digest_version: prepared.request_ref().digest_version(),
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: [2; 32],
            },
        )
        .unwrap();
    let guard = super::super::super::super::support::guard();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        fixture.execution.as_ref(),
        CredentialDispatchAuthority::new(&fixture.credentials, &fixture.launch),
        &Adapter,
        &StreamEffect,
        guard.as_ref(),
    );
    let outcome = futures::executor::block_on(coordinator.dispatch(
        runne_application::provider::ProviderCoordinatorRequest {
            call,
            principal_id: "principal-1".into(),
            conversation_id: conversation_id(fixture),
            taskrun_id: fixture.taskrun_id,
            execution_attempt_id: fixture.claim_identity.attempt_id,
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            requested_input_tokens,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: format!("unknown-successor-effect-{}", fixture.taskrun_id),
        },
    ))
    .unwrap();
    let ProviderCoordinatorOutcome::Streaming { .. } = outcome else {
        panic!("lawful mock adapter stream expected")
    };
    fixture.version = 4;
}

fn conversation_id(fixture: &Fixture) -> runne_domain::id::ConversationId {
    let stream = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    match stream.events[0].payload() {
        runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
            conversation_id, ..
        } => *conversation_id,
        _ => panic!("canonical submitted TaskRun expected"),
    }
}

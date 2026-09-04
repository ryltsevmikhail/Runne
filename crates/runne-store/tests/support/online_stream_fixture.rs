use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::{ProviderAuthorityIssueRequest, ProviderCoordinatorRequest};
use runne_provider::*;
use runne_store::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderCoordinatorOutcome,
    ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    ProviderRuntimeLaunchCapability, SqliteProviderDispatchCoordinator,
    SqliteProviderExecutionStore, VersionedProviderExecutionBinding,
};

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}
struct Transport(
    Option<ProviderStreamId>,
    std::sync::Mutex<Option<ProviderDispatchClaim>>,
    std::sync::atomic::AtomicBool,
);
impl ProviderEffectPort for Transport {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        *self.1.lock().unwrap() = Some(request.claim().clone());
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async {
            assert!(
                !self.2.swap(true, std::sync::atomic::Ordering::SeqCst),
                "replay must not dispatch again"
            );
            match self.0 {
                Some(stream) => Ok(stream),
                None => std::future::pending().await,
            }
        })
    }
}
impl ProviderPort for Transport {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { panic!("legacy dispatch forbidden") })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { panic!("fixture only opens a stream") })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(CancelDisposition::Requested) })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}
struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

/// Uses production enrollment/admission/effect/publication; only transport is scripted.
pub fn start(
    database: &super::validated_reopen::ProviderTestDatabase,
    execution: &SqliteProviderExecutionStore,
    launch: &ProviderRuntimeLaunchCapability,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    stream: ProviderStreamId,
    discriminator: u8,
) -> (
    Box<VersionedProviderExecutionBinding>,
    ProviderDispatchClaim,
) {
    let (binding, claim) = run(
        database,
        execution,
        launch,
        call,
        request,
        Some(stream),
        discriminator,
    );
    (binding.unwrap(), claim)
}

/// Drops the coordinator only after its real durable effect start reaches transport.
#[allow(
    dead_code,
    reason = "Shared fixture; only rotation audit needs a pending transport"
)]
pub fn start_pending(
    database: &super::validated_reopen::ProviderTestDatabase,
    execution: &SqliteProviderExecutionStore,
    launch: &ProviderRuntimeLaunchCapability,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    discriminator: u8,
) -> ProviderDispatchClaim {
    let (binding, claim) = run(
        database,
        execution,
        launch,
        call,
        request,
        None,
        discriminator,
    );
    assert!(binding.is_none());
    claim
}

fn run(
    database: &super::validated_reopen::ProviderTestDatabase,
    execution: &SqliteProviderExecutionStore,
    launch: &ProviderRuntimeLaunchCapability,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    stream: Option<ProviderStreamId>,
    discriminator: u8,
) -> (
    Option<Box<VersionedProviderExecutionBinding>>,
    ProviderDispatchClaim,
) {
    use std::future::Future as _;
    use std::task::Poll;
    let exists: bool = database.query_connection().query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id=?1 AND active_credential_version IS NOT NULL)",
        [request.provider_id.as_str()], |row| row.get(0),
    ).unwrap();
    let credential = if exists {
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_connection(
            database.connection(),
        )
        .unwrap()
    } else {
        super::online_credential_fixture::credential(
            database,
            request.provider_id.as_str(),
            discriminator,
        )
    };
    let dispatch = database.dispatch();
    let transport = Transport(
        stream,
        std::sync::Mutex::new(None),
        std::sync::atomic::AtomicBool::new(false),
    );
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        execution,
        CredentialDispatchAuthority::new(&credential, launch),
        &transport,
        &transport,
        &Guard,
    );
    let coordinator_request = ProviderCoordinatorRequest {
        call,
        principal_id: request.principal_id.clone(),
        conversation_id: request.conversation_id,
        taskrun_id: request.taskrun_id,
        execution_attempt_id: request.execution_attempt_id,
        profile_digest: request.prepared.profile_digest,
        pricing_revision_digest: request.pricing_revision_digest,
        requested_input_tokens: request.requested_input_tokens,
        requested_output_tokens: request.requested_output_tokens.try_into().unwrap(),
        max_cost_micros: request.max_cost_micros,
        currency: request.currency.clone(),
        provider_idempotency_key: request.provider_idempotency_key.clone(),
    };
    let mut pending = Box::pin(coordinator.dispatch(coordinator_request.clone()));
    let outcome =
        futures::executor::block_on(std::future::poll_fn(|cx| match pending.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some(result.unwrap())),
            Poll::Pending if stream.is_none() => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }));
    assert!(transport.2.load(std::sync::atomic::Ordering::SeqCst));
    drop(pending);
    let claim = transport.1.lock().unwrap().take().unwrap();
    match outcome {
        Some(ProviderCoordinatorOutcome::Streaming { binding }) => {
            assert_eq!(
                futures::executor::block_on(coordinator.dispatch(coordinator_request)).unwrap(),
                ProviderCoordinatorOutcome::Existing {
                    state: ProviderRepositoryState::Streaming
                }
            );
            (Some(binding), claim)
        }
        None => (None, claim),
        other => panic!("expected online Streaming, got {other:?}"),
    }
}

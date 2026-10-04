#![cfg(test)]

// Local fixture: kept inside the daemon source-boundary scan root.
use runne_application::provider::{ProviderAuthorityIssueRequest, ProviderCoordinatorRequest};
use runne_provider::*;
use runne_store::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderCoordinatorOutcome,
    ProviderEffectStartReceipt, ProviderRuntimeLaunchCapability, ProviderSecondaryProfileGrant,
    SqliteProviderDispatchCoordinator, SqliteProviderExecutionStore,
    VersionedProviderExecutionBinding,
};

#[path = "stream_transport.rs"]
mod stream_transport;
use stream_transport::{Guard, Transport};

pub struct OnlineDispatchStream<'a> {
    pub dispatch: &'a runne_store::provider::SqliteProviderDispatchStore,
    pub execution: &'a SqliteProviderExecutionStore,
    pub credential: &'a runne_store::provider::SqliteProviderCredentialLifecycleStore,
    pub launch: &'a ProviderRuntimeLaunchCapability,
    pub call: ProviderCall,
    pub request: &'a ProviderAuthorityIssueRequest,
    pub provider: &'a dyn crate::canonical_provider::CanonicalProviderEffect,
    pub stream: Option<ProviderStreamId>,
    pub secondary_grant: Option<&'a ProviderSecondaryProfileGrant>,
}

pub fn run_with_stores(
    setup: OnlineDispatchStream<'_>,
) -> (
    Option<Box<VersionedProviderExecutionBinding>>,
    ProviderDispatchClaim,
    CredentialDispatchBinding,
    ProviderEffectStartReceipt,
) {
    let OnlineDispatchStream {
        dispatch,
        execution,
        credential,
        launch,
        call,
        request,
        provider,
        stream,
        secondary_grant,
    } = setup;
    use std::future::Future as _;
    use std::task::Poll;
    let transport = Transport(
        stream,
        std::sync::Mutex::new(None),
        std::sync::atomic::AtomicBool::new(false),
        std::sync::Mutex::new(None),
        std::sync::Mutex::new(None),
        tokio::sync::Notify::new(),
        provider,
    );
    let coordinator = SqliteProviderDispatchCoordinator::new(
        dispatch,
        execution,
        CredentialDispatchAuthority::new(credential, launch),
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
    let mut pending = Box::pin(async {
        match secondary_grant {
            Some(grant) => {
                coordinator
                    .dispatch_secondary_profile(coordinator_request.clone(), grant)
                    .await
            }
            None => coordinator.dispatch(coordinator_request.clone()).await,
        }
    });
    let outcome =
        futures::executor::block_on(std::future::poll_fn(|cx| match pending.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(Some(result.unwrap_or_else(|error| {
                panic!("provider coordinator fixture failed before adapter: {error:?}")
            }))),
            Poll::Pending
                if stream.is_none() && transport.2.load(std::sync::atomic::Ordering::SeqCst) =>
            {
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }));
    assert!(
        transport.2.load(std::sync::atomic::Ordering::SeqCst),
        "coordinator did not reach effect start; outcome={outcome:?} claim={} credential={} receipt={}",
        transport.1.lock().unwrap().is_some(),
        transport.3.lock().unwrap().is_some(),
        transport.4.lock().unwrap().is_some(),
    );
    drop(pending);
    let claim = transport.1.lock().unwrap().take().unwrap();
    let credential = transport.3.lock().unwrap().take().unwrap();
    let receipt = transport.4.lock().unwrap().take().unwrap();
    match outcome {
        Some(ProviderCoordinatorOutcome::Streaming { binding }) => {
            assert_eq!(
                futures::executor::block_on(async {
                    match secondary_grant {
                        Some(grant) => {
                            coordinator
                                .dispatch_secondary_profile(coordinator_request, grant)
                                .await
                        }
                        None => coordinator.dispatch(coordinator_request).await,
                    }
                })
                .unwrap(),
                ProviderCoordinatorOutcome::Existing {
                    state: ProviderRepositoryState::Streaming
                }
            );
            (Some(binding), claim, credential, receipt)
        }
        None => (None, claim, credential, receipt),
        other => panic!("expected online Streaming, got {other:?}"),
    }
}

pub async fn run_with_stores_async(
    setup: OnlineDispatchStream<'_>,
) -> (
    Option<Box<VersionedProviderExecutionBinding>>,
    ProviderDispatchClaim,
    CredentialDispatchBinding,
    ProviderEffectStartReceipt,
) {
    let OnlineDispatchStream {
        dispatch,
        execution,
        credential,
        launch,
        call,
        request,
        provider,
        stream,
        secondary_grant,
    } = setup;
    let transport = Transport(
        stream,
        std::sync::Mutex::new(None),
        std::sync::atomic::AtomicBool::new(false),
        std::sync::Mutex::new(None),
        std::sync::Mutex::new(None),
        tokio::sync::Notify::new(),
        provider,
    );
    let coordinator = SqliteProviderDispatchCoordinator::new(
        dispatch,
        execution,
        CredentialDispatchAuthority::new(credential, launch),
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
    let dispatch = async {
        match secondary_grant {
            Some(grant) => {
                coordinator
                    .dispatch_secondary_profile(coordinator_request.clone(), grant)
                    .await
            }
            None => coordinator.dispatch(coordinator_request.clone()).await,
        }
    };
    tokio::pin!(dispatch);
    let outcome = if stream.is_none() {
        let started = transport.5.notified();
        tokio::pin!(started);
        tokio::select! {
            result = &mut dispatch => Some(result.unwrap_or_else(|error| panic!("coordinator fixture failed: {error:?}"))),
            _ = &mut started => None,
        }
    } else {
        Some(
            dispatch
                .await
                .unwrap_or_else(|error| panic!("coordinator fixture failed: {error:?}")),
        )
    };
    assert!(transport.2.load(std::sync::atomic::Ordering::SeqCst));
    let claim = transport.1.lock().unwrap().take().unwrap();
    let credential = transport.3.lock().unwrap().take().unwrap();
    let receipt = transport.4.lock().unwrap().take().unwrap();
    match outcome {
        Some(ProviderCoordinatorOutcome::Streaming { binding }) => {
            (Some(binding), claim, credential, receipt)
        }
        None => (None, claim, credential, receipt),
        other => panic!("expected online Streaming, got {other:?}"),
    }
}

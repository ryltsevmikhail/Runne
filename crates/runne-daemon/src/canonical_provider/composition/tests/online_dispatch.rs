use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_provider::{ProviderCall, ProviderDispatchClaim, ProviderStreamId};
use runne_store::provider::ProviderSecondaryProfileGrant;
use runne_store::schema::ManagedConnection;

use super::super::DaemonCanonicalProviderService;

mod final_send_cancel;
mod observer_fairness;
pub(in crate::canonical_provider::composition::tests) mod profile_fixture;
mod stream;

#[tokio::test(flavor = "current_thread")]
async fn zai_adapter_rechecks_public_cancellation_before_transport_send() {
    profile_fixture::assert_cancel_before_send(profile_fixture::chat_completions_fixture()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn responses_adapter_rechecks_public_cancellation_before_transport_send() {
    profile_fixture::assert_cancel_before_send(profile_fixture::responses_fixture()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn radius_adapter_rechecks_public_cancellation_before_transport_send() {
    profile_fixture::assert_cancel_before_send(profile_fixture::radius_fixture()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn native_adapter_rechecks_public_cancellation_before_transport_send() {
    profile_fixture::assert_cancel_before_send(profile_fixture::native_fixture()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn openai_foreground_rechecks_public_cancellation_before_post() {
    profile_fixture::openai_foreground_fixture_cancellation_denies_post().await;
}

#[tokio::test(flavor = "current_thread")]
async fn deepseek_foreground_rechecks_public_cancellation_before_post() {
    profile_fixture::deepseek_foreground_fixture_cancellation_denies_post().await;
}

#[tokio::test(flavor = "current_thread")]
async fn local_engine_rechecks_public_cancellation_before_execution() {
    let (fixture, invocations) = profile_fixture::local_engine_fixture();
    profile_fixture::assert_cancel_before_local_execution(fixture, invocations).await;
}

/// Keeps enrollment, admission and effect publication real; only transport is scripted.
pub(super) fn start(
    service: &DaemonCanonicalProviderService,
    _connection: ManagedConnection,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    stream: Option<ProviderStreamId>,
    secondary_grant: Option<&ProviderSecondaryProfileGrant>,
) -> ProviderDispatchClaim {
    start_with_adapter(
        service,
        _connection,
        call,
        request,
        stream,
        secondary_grant,
        service.adapter.as_ref(),
    )
}

pub(super) fn start_with_adapter(
    service: &DaemonCanonicalProviderService,
    _connection: ManagedConnection,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    stream: Option<ProviderStreamId>,
    secondary_grant: Option<&ProviderSecondaryProfileGrant>,
    adapter: &dyn crate::canonical_provider::CanonicalProviderEffect,
) -> ProviderDispatchClaim {
    let (binding, claim, _, _) = stream::run_with_stores(stream::OnlineDispatchStream {
        dispatch: service.dispatch_store.as_ref(),
        execution: service.execution_store.as_ref(),
        credential: service.credential_store.as_ref(),
        launch: &service.launch_capability,
        call,
        request,
        provider: adapter,
        stream,
        secondary_grant,
    });
    assert_eq!(binding.is_some(), stream.is_some());
    claim
}

pub(super) async fn start_with_receipt(
    service: &DaemonCanonicalProviderService,
    _connection: ManagedConnection,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
) -> (
    ProviderDispatchClaim,
    runne_store::provider::CredentialDispatchBinding,
    runne_store::provider::ProviderEffectStartReceipt,
) {
    let (_, claim, binding, receipt) =
        stream::run_with_stores_async(stream::OnlineDispatchStream {
            dispatch: service.dispatch_store.as_ref(),
            execution: service.execution_store.as_ref(),
            credential: service.credential_store.as_ref(),
            launch: &service.launch_capability,
            call,
            request,
            provider: service.adapter.as_ref(),
            stream: None,
            secondary_grant: None,
        })
        .await;
    (claim, binding, receipt)
}

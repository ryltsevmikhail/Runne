use std::sync::Arc;

use runne_provider::{
    ProviderRecoveryDispatchContextProvider, RemoteResponseId, TextProviderProfile,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;

use super::super::super::recovery_audit::part_08;

pub(super) async fn persist_saved_identity(
    service: &crate::canonical_provider::composition::DaemonCanonicalProviderService,
    route: &crate::canonical_provider::execution::SecondaryProfileRoute,
    saved: &part_08::setup::SavedRemoteDispatch,
    response_id: &str,
) {
    let provider = runne_provider::ProviderId::new(route.provider_id.as_ref()).unwrap();
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&service.keyring),
        Arc::clone(&service.execution_store),
    );
    let context = committer
        .for_new_dispatch(
            &saved.claim,
            &provider,
            &provider,
            route.profile.profile_id(),
        )
        .await
        .unwrap();
    context
        .persist_request(&saved.rendered_request)
        .await
        .unwrap();
    context
        .commit_response_id(&RemoteResponseId::new(response_id).unwrap())
        .await
        .unwrap();
}

use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_provider::{ProviderCall, ProviderDispatchClaim, ProviderStreamId};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use super::super::DaemonCanonicalProviderService;

mod credential;
mod stream;

/// Keeps enrollment, admission and effect publication real; only transport is scripted.
pub(super) fn start(
    service: &DaemonCanonicalProviderService,
    connection: ManagedConnection,
    call: ProviderCall,
    request: &ProviderAuthorityIssueRequest,
    stream: Option<ProviderStreamId>,
) -> ProviderDispatchClaim {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id=?1 AND active_credential_version IS NOT NULL)",
        [request.provider_id.as_str()], |row| row.get(0),
    ).unwrap();
    let credential = if exists {
        SqliteProviderCredentialLifecycleStore::open_with_connection(connection).unwrap()
    } else {
        credential::credential_with_connection(connection, request.provider_id.as_str(), 91)
    };
    let (binding, claim) = stream::run_with_stores(
        service.dispatch_store.as_ref(),
        service.execution_store.as_ref(),
        &credential,
        &service.launch_capability,
        call,
        request,
        stream,
    );
    assert_eq!(binding.is_some(), stream.is_some());
    claim
}

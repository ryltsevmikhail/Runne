use super::super::DurableProviderAdmission;
use super::super::authority_test_support::configured_connection;
use super::Fixture;
use crate::provider::SqliteProviderCredentialLifecycleStore;
use crate::provider::dispatch_store::{MarkProviderStreaming, SqliteProviderDispatchStore};

pub fn start_online_stream(
    fixture: &Fixture,
    lifecycle: &SqliteProviderCredentialLifecycleStore,
    admission: &DurableProviderAdmission,
) {
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    let (_, credential_binding) = authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), admission.claim(), &credential_binding)
        .unwrap();
    let dispatch = SqliteProviderDispatchStore::open_with_connection(
        fixture.path.to_str().unwrap(),
        configured_connection(&fixture.path),
    )
    .unwrap();
    dispatch
        .mark_streaming_online(
            &MarkProviderStreaming {
                attempt_id: admission.claim().attempt_id,
                fencing_token: admission.claim().fencing_token,
                stream_id: runne_provider::ProviderStreamId::from_bytes([44; 16]),
            },
            || 100,
        )
        .unwrap();
}

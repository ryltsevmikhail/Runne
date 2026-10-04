use super::*;
use crate::provider::credential_lifecycle::online_test_support::revoke;
use crate::provider::execution_store::secondary_profile_grant_tests as helpers;
use crate::provider::{MarkProviderStreaming, SqliteProviderDispatchStore};
use runne_application::provider::{
    ProviderExecutionError, ProviderJournalAppendRequest, ProviderPollRequest,
};
use runne_provider::ProviderCredentialEnrollmentStore;

#[test]
fn secondary_publication_keeps_online_credential_fence_and_terminal_accounting() {
    use crate::provider::credential_lifecycle::online_test_support::provider;

    let (fixture, lifecycle) = helpers::secondary_online_fixture();
    let grant = helpers::grant(&fixture, "openai");
    let admission = helpers::winner(helpers::issue(&fixture, &grant, "openai", 91));
    let claim = admission.claim();
    let pending = helpers::winner(helpers::issue(&fixture, &grant, "openai", 92));
    let pending_claim = pending.claim();
    let primary_before = fixture.store.utilization().unwrap();
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), claim, 100)
        .unwrap();
    let pending_authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), pending_claim, 100)
        .unwrap();
    assert_eq!(provider().as_str(), "openai");
    let (_, effect_binding) = authorization.split();
    let (_, pending_effect_binding) = pending_authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), claim, &effect_binding)
        .unwrap();
    fixture
        .store
        .start_online_effect(fixture.launch(), pending_claim, &pending_effect_binding)
        .unwrap();
    let dispatch = SqliteProviderDispatchStore::open_with_connection(
        fixture.path.to_str().unwrap(),
        crate::provider::execution_store::authority_test_support::configured_connection(
            &fixture.path,
        ),
    )
    .unwrap();
    let publication = MarkProviderStreaming {
        attempt_id: claim.attempt_id,
        fencing_token: claim.fencing_token,
        stream_id: ProviderStreamId::from_bytes([92; 16]),
    };
    let pending_publication = MarkProviderStreaming {
        attempt_id: pending_claim.attempt_id,
        fencing_token: pending_claim.fencing_token,
        stream_id: ProviderStreamId::from_bytes([96; 16]),
    };
    dispatch
        .mark_streaming_online(&publication, || 100)
        .unwrap();
    dispatch
        .mark_streaming_online(&pending_publication, || 100)
        .unwrap();
    helpers::append_terminal(&fixture, &admission);
    let revoke = revoke(93, "secondary-online-revoke", 2, 2);
    ProviderCredentialEnrollmentStore::begin(&lifecycle, revoke).unwrap();

    assert_eq!(
        dispatch.mark_streaming_online(&publication, || 101),
        Err(crate::provider::ProviderStoreError::StaleFencingToken),
        "secondary grant must not bypass revoked online credential head"
    );
    assert_eq!(
        dispatch.mark_streaming_online(&pending_publication, || 101),
        Err(crate::provider::ProviderStoreError::StaleFencingToken),
        "pending secondary publication remains fenced by the credential head"
    );
    assert_eq!(
        fixture.store.begin_provider_poll(&ProviderPollRequest {
            attempt_id: pending_claim.attempt_id,
            fencing_token: pending_claim.fencing_token,
            cursor: 0,
            profile_digest: [2; 32],
            runtime_generation: 11,
        }),
        Err(ProviderExecutionError::StaleGeneration),
        "revoked online credential must also close ordinary polling"
    );
    assert_eq!(
        fixture
            .store
            .append_encrypted_event(&ProviderJournalAppendRequest {
                attempt_id: pending_claim.attempt_id,
                fencing_token: pending_claim.fencing_token,
                sequence: 0,
                event_kind: 1,
                terminal: false,
                call_digest_version: runne_provider::ProviderCallDigestVersion::V2,
                profile_digest: [2; 32],
                runtime_generation: 11,
                key: runne_application::provider::ProviderJournalKeyBinding::new(
                    [9; 16], 1, [1; 16], 7,
                )
                .unwrap(),
                encrypted: helpers::encrypted(94, 95),
            }),
        Err(ProviderExecutionError::StaleGeneration),
        "revoked online credential must not append new journal data"
    );
    assert_eq!(
        helpers::runtime_settlement::finalize(&fixture, &admission),
        ProviderTerminalCommitOutcome::Committed,
        "a terminal encrypted before revoke may still settle its exact ledger"
    );
    let (tokens, costs) = fixture
        .store
        .secondary_profile_utilization(fixture.launch(), &grant)
        .unwrap();
    assert_eq!((tokens.reserved, tokens.settled), (1_536, 1_400));
    assert_eq!((costs.reserved, costs.settled), (50_000, 40_000));
    assert_eq!(fixture.store.utilization().unwrap(), primary_before);
}

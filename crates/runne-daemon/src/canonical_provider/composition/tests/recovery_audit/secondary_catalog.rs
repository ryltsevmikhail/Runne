use super::fixture::Harness;
use runne_application::provider::ProviderSecondaryProfileGrantSpec;
use runne_provider::ProviderId;
use runne_provider_openai::{
    OPENAI_RESPONSES_BACKGROUND_PROFILE_ID, OPENAI_RESPONSES_PROFILE_ID, OpenAiResponsesTextProfile,
};

#[tokio::test]
async fn exact_revoked_secondary_catalog_does_not_block_primary_startup() {
    let harness = Harness::new().await;
    let profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .unwrap();
    let provider = ProviderId::new(profile.provider_id()).unwrap();
    let spec = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        OPENAI_RESPONSES_BACKGROUND_PROFILE_ID,
        profile.provider_id(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        1_000,
        50_000,
    )
    .unwrap();
    harness.revoke_secondary_spec(spec.clone());
    let changed_limits = ProviderSecondaryProfileGrantSpec::new(
        &provider,
        OPENAI_RESPONSES_BACKGROUND_PROFILE_ID,
        profile.provider_id(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        1_000,
        50_001,
    )
    .unwrap();
    assert!(
        harness
            .try_compose_with_catalog(harness.catalog_for_test(changed_limits))
            .await
            .is_err()
    );
    let service = harness
        .compose_with_catalog(harness.catalog_for_test(spec))
        .await;
    assert_eq!(
        service.selected_profile_identity().profile_id(),
        OPENAI_RESPONSES_PROFILE_ID
    );
}

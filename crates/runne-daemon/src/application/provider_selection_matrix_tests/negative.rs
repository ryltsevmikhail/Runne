use super::super::*;
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};

use super::support::cloud_settings;

#[test]
fn matrix_rejects_tampered_profile_and_missing_owner_bounds() {
    let profile = runne_provider_chat_completions::generic_profiles()
        .first()
        .unwrap();
    let tampered = ProviderActivationBindingV1::new(
        ProviderActivationModeV1::GenericChatCompletionsTextV1,
        profile.profile_id,
        [7; 32],
    )
    .unwrap();
    assert!(select_provider_runtime(&ProviderActivation::from_binding(tampered)).is_err());
    let mut settings = cloud_settings(false);
    settings.cloud_max_model_output_tokens = None;
    assert!(
        crate::provider_activation::cloud::configured_profile(
            "gocode-cloud/nvidia/meta/llama-3.1-8b-instruct/1",
            &settings
        )
        .is_err()
    );
}

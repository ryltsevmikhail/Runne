use super::super::*;
use crate::provider_activation::{ProviderAccountingMode, ProviderActivationSettings};
use runne_api::{ProviderActivationBindingV1, ProviderActivationModeV1};
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput, TextProviderProfile,
};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead, SecureStoreError,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) struct DenyingMaterializer;
impl ProviderCredentialDispatchMaterializer for DenyingMaterializer {
    fn materialize_active(
        &self,
        _: ProviderCredentialDispatchRead<'_>,
    ) -> Result<runne_secure_store::ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::CredentialAccessDenied)
    }
}

pub(super) fn call_for(selected: &SelectedProviderRuntime) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([0x72; 16]),
        ModelRef::new(
            ProviderId::new(selected.provider_id.as_ref()).unwrap(),
            selected.model_id.as_ref(),
            selected.model_revision.as_ref(),
        )
        .unwrap(),
        [0; 32],
        if selected.provider_id == "openai-codex" {
            selected.profile.max_output_tokens()
        } else {
            selected.profile.max_output_tokens().min(256)
        },
        selected.profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

pub(super) fn assert_selects_and_prepares(activation: ProviderActivation, expected: &str) {
    let selected = select_provider_runtime(&activation)
        .unwrap_or_else(|error| panic!("{expected} selection failed: {error}"))
        .expect("runtime");
    assert_eq!(selected.provider_id, expected);
    let directory = tempfile::tempdir().expect("temporary provider store");
    let store = Arc::new(
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_at(
            &{
                let daemon = directory.path().join("runne-daemon");
                std::fs::create_dir_all(&daemon).unwrap();
                daemon.join("matrix.sqlite")
            },
            0,
        )
        .expect("provider store"),
    );
    let effect = (selected.adapter_factory)(Arc::new(DenyingMaterializer), store).expect("effect");
    effect
        .prepare(&call_for(&selected))
        .unwrap_or_else(|error| panic!("{expected} prepare failed: {error}"));
}

pub(super) fn generic_binding(
    profile: &runne_provider_chat_completions::GenericChatProfile,
) -> ProviderActivation {
    ProviderActivation::from_binding(
        ProviderActivationBindingV1::new(
            ProviderActivationModeV1::GenericChatCompletionsTextV1,
            profile.profile_id,
            profile.profile.profile_digest(),
        )
        .unwrap(),
    )
}

pub(super) fn native_binding(profile_id: &str, digest: [u8; 32]) -> ProviderActivation {
    ProviderActivation::from_binding(
        ProviderActivationBindingV1::new(
            ProviderActivationModeV1::NativeTextV1,
            profile_id,
            digest,
        )
        .unwrap(),
    )
}

pub(super) fn vertex_digest(project: &str, location: &str) -> [u8; 32] {
    Sha256::digest(format!(
        "runne/native-profile/v2|google-vertex|gocode-native/google-vertex/gemini-2.5-flash/1|gemini-2.5-flash|pi-0.85.1|https://{location}-aiplatform.googleapis.com|project:{project}|location:{location}|vertex_bearer|1048576|64:262144:1966080:983040:65536:8388608:65536|payg:300000:2500000:30000:0"
    ).as_bytes()).into()
}

pub(super) fn cloud_settings(gateway: bool) -> ProviderActivationSettings {
    ProviderActivationSettings {
        cloud_region_or_account: Some(if gateway { "acct" } else { "us-east-1" }.into()),
        cloud_gateway: gateway.then(|| "runne".into()),
        cloud_input_micros_per_million: Some(2_000_000),
        cloud_output_micros_per_million: Some(10_000_000),
        cloud_cached_input_micros_per_million: Some(200_000),
        cloud_context_tokens: Some(32_768),
        cloud_max_output_tokens: Some(4_096),
        cloud_max_model_output_tokens: Some(8_192),
        cloud_max_input_entries: Some(64),
        cloud_max_input_entry_bytes: Some(8_192),
        cloud_max_input_bytes: Some(16_384),
        cloud_max_request_bytes: Some(32 * 1024),
        cloud_max_response_frame_bytes: Some(32 * 1024),
        cloud_gateway_billing: gateway.then(|| "stored_byok".into()),
        accounting_mode: Some(ProviderAccountingMode::Payg),
        ..Default::default()
    }
}

pub(super) const RADIUS_CATALOG: &[u8] = br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"fixture-model","name":"Fixture","reasoning":false,"input":["text"],"contextWindow":8192,"maxTokens":1024,"cost":{"input":1,"output":2,"cacheRead":0.1,"cacheWrite":0}}]}"#;

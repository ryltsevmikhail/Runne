// Deserialization and validation of non-secret provider settings.
use crate::provider_activation::{ProviderAccountingMode, ProviderActivationSettings};

/// Non-secret settings for dynamic provider routes.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalProviderSettingsConfig {
    vertex_project: Option<String>,
    vertex_location: Option<String>,
    radius_catalog_json: Option<String>,
    radius_model_id: Option<String>,
    radius_revision: Option<String>,
    accounting_mode: Option<String>,
    responses_resource: Option<String>,
    responses_deployment: Option<String>,
    responses_pricing_digest: Option<String>,
    responses_input_micros_per_million: Option<u64>,
    responses_output_micros_per_million: Option<u64>,
    responses_cached_input_micros_per_million: Option<u64>,
    responses_max_output_tokens: Option<u32>,
    responses_context_tokens: Option<u32>,
    cloud_region_or_account: Option<String>,
    cloud_gateway: Option<String>,
    cloud_input_micros_per_million: Option<u64>,
    cloud_output_micros_per_million: Option<u64>,
    cloud_cached_input_micros_per_million: Option<u64>,
    cloud_context_tokens: Option<u32>,
    cloud_max_output_tokens: Option<u32>,
    cloud_max_model_output_tokens: Option<u32>,
    cloud_max_input_entries: Option<usize>,
    cloud_max_input_entry_bytes: Option<usize>,
    cloud_max_input_bytes: Option<usize>,
    cloud_max_request_bytes: Option<usize>,
    cloud_max_response_frame_bytes: Option<usize>,
    cloud_gateway_billing: Option<String>,
}

impl TryFrom<&ExternalProviderSettingsConfig> for ProviderActivationSettings {
    type Error = DaemonError;

    fn try_from(value: &ExternalProviderSettingsConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            vertex_project: value.vertex_project.clone(),
            vertex_location: value.vertex_location.clone(),
            radius_catalog: value
                .radius_catalog_json
                .as_ref()
                .map(|json| json.as_bytes().to_vec()),
            radius_model_id: value.radius_model_id.clone(),
            radius_revision: value.radius_revision.clone(),
            accounting_mode: value
                .accounting_mode
                .as_deref()
                .map(parse_accounting_mode)
                .transpose()?,
            responses_resource: value.responses_resource.clone(),
            responses_deployment: value.responses_deployment.clone(),
            responses_pricing_digest: value
                .responses_pricing_digest
                .as_deref()
                .map(parse_digest)
                .transpose()?,
            responses_input_micros_per_million: value.responses_input_micros_per_million,
            responses_output_micros_per_million: value.responses_output_micros_per_million,
            responses_cached_input_micros_per_million: value
                .responses_cached_input_micros_per_million,
            responses_max_output_tokens: value.responses_max_output_tokens,
            responses_context_tokens: value.responses_context_tokens,
            cloud_region_or_account: value.cloud_region_or_account.clone(),
            cloud_gateway: value.cloud_gateway.clone(),
            cloud_input_micros_per_million: value.cloud_input_micros_per_million,
            cloud_output_micros_per_million: value.cloud_output_micros_per_million,
            cloud_cached_input_micros_per_million: value.cloud_cached_input_micros_per_million,
            cloud_context_tokens: value.cloud_context_tokens,
            cloud_max_output_tokens: value.cloud_max_output_tokens,
            cloud_max_model_output_tokens: value.cloud_max_model_output_tokens,
            cloud_max_input_entries: value.cloud_max_input_entries,
            cloud_max_input_entry_bytes: value.cloud_max_input_entry_bytes,
            cloud_max_input_bytes: value.cloud_max_input_bytes,
            cloud_max_request_bytes: value.cloud_max_request_bytes,
            cloud_max_response_frame_bytes: value.cloud_max_response_frame_bytes,
            cloud_gateway_billing: value.cloud_gateway_billing.clone(),
        })
    }
}

fn parse_digest(value: &str) -> Result<[u8; 32], DaemonError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| DaemonError::Config("invalid provider pricing digest".into()))
}

fn parse_accounting_mode(value: &str) -> Result<ProviderAccountingMode, DaemonError> {
    match value {
        "payg" => Ok(ProviderAccountingMode::Payg),
        "subscription" => Ok(ProviderAccountingMode::Subscription),
        "token_plan" => Ok(ProviderAccountingMode::TokenPlan),
        _ => Err(DaemonError::Config(
            "invalid provider accounting mode".into(),
        )),
    }
}

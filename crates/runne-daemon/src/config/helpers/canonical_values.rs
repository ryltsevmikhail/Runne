use super::*;

// This argument list mirrors every serialized configuration input field.
#[allow(clippy::too_many_arguments)]
pub(super) fn canonical_values_map(
    schema_version: i64,
    db_path: &str,
    http_bind: &str,
    replay_integrity_key_path: &str,
    max_in_flight: u32,
    shutdown_timeout_ms: u64,
    provider_activation: &ProviderActivationBindingV1,
    provider_settings: Option<&crate::provider_activation::ProviderActivationSettings>,
    d2_tool_budget: Option<D2SafeToolLoopBudgetConfig>,
) -> serde_json::Map<String, serde_json::Value> {
    // Insert keys in alphabetical order — serde_json::Map is BTreeMap-backed,
    // so iteration order matches insertion order, giving us canonical output.
    let mut map = serde_json::Map::new();
    map.insert("db_path".into(), serde_json::Value::String(db_path.into()));
    if let Some(budget) = d2_tool_budget {
        map.insert(
            "d2_safe_tool_loop_budget".into(),
            serde_json::json!({
                "token_budget_limit": budget.token_budget_limit,
                "cost_budget_limit_micros": budget.cost_budget_limit_micros,
            }),
        );
    }
    map.insert(
        "http_bind".into(),
        serde_json::Value::String(http_bind.into()),
    );
    map.insert(
        "max_in_flight".into(),
        serde_json::Value::Number((max_in_flight).into()),
    );
    map.insert(
        "schema_version".into(),
        serde_json::Value::Number((schema_version).into()),
    );
    map.insert(
        "shutdown_timeout_ms".into(),
        serde_json::Value::Number((shutdown_timeout_ms).into()),
    );
    map.insert(
        "replay_integrity_key_path".into(),
        serde_json::Value::String(replay_integrity_key_path.into()),
    );
    map.insert(
        "provider_activation".into(),
        serde_json::json!({
            "mode": provider_activation.mode().as_str(),
            "profile_digest": hex::encode(provider_activation.profile_digest()),
            "profile_id": provider_activation.profile_id(),
        }),
    );
    if let Some(settings) = provider_settings {
        map.insert(
            "provider_activation_settings".into(),
            serde_json::json!({
                "vertex_project": settings.vertex_project.as_deref(),
                "vertex_location": settings.vertex_location.as_deref(),
                "radius_catalog_digest": settings.radius_catalog.as_ref().map(|bytes| hex::encode(Sha256::digest(bytes))),
                "radius_model_id": settings.radius_model_id.as_deref(),
                "radius_revision": settings.radius_revision.as_deref(),
                "accounting_mode": settings.accounting_mode.map(|mode| match mode {
                    crate::provider_activation::ProviderAccountingMode::Payg => "payg",
                    crate::provider_activation::ProviderAccountingMode::Subscription => "subscription",
                    crate::provider_activation::ProviderAccountingMode::TokenPlan => "token_plan",
                }),
                "responses_resource": settings.responses_resource.as_deref(),
                "responses_deployment": settings.responses_deployment.as_deref(),
                "responses_pricing_digest": settings.responses_pricing_digest.map(hex::encode),
                "responses_input_micros_per_million": settings.responses_input_micros_per_million,
                "responses_output_micros_per_million": settings.responses_output_micros_per_million,
                "responses_cached_input_micros_per_million": settings.responses_cached_input_micros_per_million,
                "responses_max_output_tokens": settings.responses_max_output_tokens,
                "responses_context_tokens": settings.responses_context_tokens,
                "cloud_region_or_account": settings.cloud_region_or_account.as_deref(),
                "cloud_gateway": settings.cloud_gateway.as_deref(),
                "cloud_input_micros_per_million": settings.cloud_input_micros_per_million,
                "cloud_output_micros_per_million": settings.cloud_output_micros_per_million,
                "cloud_cached_input_micros_per_million": settings.cloud_cached_input_micros_per_million,
                "cloud_context_tokens": settings.cloud_context_tokens,
                "cloud_max_output_tokens": settings.cloud_max_output_tokens,
                "cloud_max_model_output_tokens": settings.cloud_max_model_output_tokens,
                "cloud_max_input_entries": settings.cloud_max_input_entries,
                "cloud_max_input_entry_bytes": settings.cloud_max_input_entry_bytes,
                "cloud_max_input_bytes": settings.cloud_max_input_bytes,
                "cloud_max_request_bytes": settings.cloud_max_request_bytes,
                "cloud_max_response_frame_bytes": settings.cloud_max_response_frame_bytes,
                "cloud_gateway_billing": settings.cloud_gateway_billing.as_deref(),
            }),
        );
    }
    map
}

/// Compute SHA-256 hex digest of canonical JSON (no whitespace, sorted keys).
pub(super) fn compute_digest(values: &serde_json::Map<String, serde_json::Value>) -> String {
    let json = serde_json::to_string(values).expect("canonical JSON serialization is infallible");
    let hash = Sha256::digest(json.as_bytes());
    hex::encode(hash)
}

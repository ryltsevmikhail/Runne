use runne_application::provider::ProviderCoordinatorRequest;
use runne_provider::{ModelRef, ProviderCall, ProviderCallId};

pub(in super::super) fn coordinator_request(
    call: u8,
    key: &str,
    path: &std::path::Path,
) -> ProviderCoordinatorRequest {
    let (conversation_id, taskrun_id, execution_attempt_id) =
        super::super::canonical_started_test_support::seed(path, call);
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([call; 16]),
            ModelRef::new(super::provider(), "model", "v1").unwrap(),
            [5; 32],
            64,
            serde_json::Value::Null,
        )
        .unwrap(),
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: key.into(),
    }
}

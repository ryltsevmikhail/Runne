use crate::{
    shared::{assert_routed_request, call},
    support::{SECRET, rejection, split_bytes, successful_sse},
};
use runne_provider_conformance::{
    ProviderFailureKind, assert_redacted_diagnostics, classify_provider_failure,
    validate_text_stream,
};

#[test]
fn profile_renderer_route_stream_and_auth_failure_conform() {
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let prepared = runne_provider_deepseek::DeepSeekResponsesTextRenderer::new(profile.clone())
        .prepare(&call(
            "deepseek",
            runne_provider_deepseek::DEEPSEEK_MODEL_ID,
            runne_provider_deepseek::DEEPSEEK_MODEL_REVISION,
            profile.binding_extension(),
        ))
        .unwrap();
    assert_routed_request(
        "POST",
        profile.origin(),
        profile.path(),
        prepared.rendered_bytes(),
    );
    let policy = runne_provider_deepseek::DeepSeekTransportPolicy::for_profile(&profile).unwrap();
    assert_eq!(
        (policy.method(), policy.origin(), policy.path()),
        ("POST", "https://api.deepseek.com", "/v1/responses")
    );
    assert!(
        !policy.follows_redirects()
            && !policy.uses_ambient_proxy()
            && !policy.automatically_retries()
    );
    let response = runne_provider_deepseek::DeepSeekTransportResponse::sse(split_bytes(
        &successful_sse(
            runne_provider_deepseek::DEEPSEEK_REQUEST_MODEL,
            runne_provider_deepseek::DEEPSEEK_SERVICE_TIER,
        ),
        7,
    ))
    .unwrap();
    let events = runne_provider_deepseek::decode_transport_response(&response).unwrap();
    assert_eq!(
        validate_text_stream(&events, "hello world", true)
            .unwrap()
            .text_delta_count(),
        2
    );
    let auth = runne_provider_deepseek::DeepSeekTransportResponse::json_rejection(401, rejection())
        .unwrap();
    let auth_events = runne_provider_deepseek::decode_transport_response(&auth).unwrap();
    validate_text_stream(&auth_events, "", false).unwrap();
    let failure =
        classify_provider_failure(Some(auth.status()), Some("authentication_failed"), None);
    assert_eq!(failure.kind(), ProviderFailureKind::Authentication);
    assert_redacted_diagnostics(SECRET, &format!("{response:?}"), &failure.to_string()).unwrap();
}

#[test]
fn empty_malformed_and_unknown_model_are_closed() {
    let empty = runne_provider_deepseek::DeepSeekTransportResponse::sse(vec![Vec::new()]).unwrap();
    assert!(runne_provider_deepseek::decode_transport_response(&empty).is_err());
    let malformed =
        runne_provider_deepseek::DeepSeekTransportResponse::sse(vec![b"not-an-event".to_vec()])
            .unwrap();
    let error = runne_provider_deepseek::decode_transport_response(&malformed).unwrap_err();
    assert_redacted_diagnostics(SECRET, &format!("{error:?}"), &error.to_string()).unwrap();
    let profile = runne_provider_deepseek::DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .unwrap();
    let wrong = call(
        "deepseek",
        "unknown-model",
        runne_provider_deepseek::DEEPSEEK_MODEL_REVISION,
        profile.binding_extension(),
    );
    assert!(matches!(
        runne_provider_deepseek::DeepSeekResponsesTextRenderer::new(profile).prepare(&wrong),
        Err(runne_provider_deepseek::DeepSeekRenderError::ProfileBindingMismatch)
    ));
    assert_eq!(
        classify_provider_failure(Some(404), Some("model_unavailable"), None).kind(),
        ProviderFailureKind::ModelUnavailable
    );
}

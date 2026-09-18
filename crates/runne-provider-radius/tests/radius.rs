use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderStreamEventKind, ProviderTerminalPricing, ProviderTextInput, TextProviderProfile,
};
use runne_provider_radius::{
    RadiusAccounting, RadiusCatalog, RadiusRenderError, RadiusRenderer, RadiusStreamDecoder,
    RadiusStreamError,
};
use serde_json::{Value, json};
use std::fmt::Write as _;

const CATALOG: &[u8] = br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"dynamic-model","name":"Dynamic","reasoning":false,"input":["text"],"cost":{"input":1,"output":2,"cacheRead":0.1,"cacheWrite":0},"contextWindow":8192,"maxTokens":1024}]}"#;

fn call(profile: &runne_provider_radius::RadiusProfile, extension: Value) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([8; 16]),
        ModelRef::new(
            ProviderId::new(profile.provider_id()).unwrap(),
            profile.model_id(),
            profile.revision(),
        )
        .unwrap(),
        [4; 32],
        16,
        extension,
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

#[test]
fn dynamic_catalog_digest_binds_renderer_and_exact_pi_shape() {
    let catalog = RadiusCatalog::from_json_at(CATALOG, "https://radius.pi.dev").unwrap();
    let profile = catalog
        .select("radius", "dynamic-model", "catalog-rev")
        .unwrap();
    let renderer = RadiusRenderer::new(profile.clone());
    let request = renderer
        .prepare(&call(&profile, renderer.binding_extension()))
        .unwrap();
    let body: Value = serde_json::from_slice(request.rendered_bytes()).unwrap();
    assert_eq!(body["model"], "dynamic-model");
    assert_eq!(body["context"]["messages"][0]["role"], "user");
    assert_eq!(body["options"]["maxTokens"], 16);
    assert_eq!(profile.accounting(), RadiusAccounting::SubscriptionQuota);
    assert_eq!(profile.currency(), "XXX");
    assert!(matches!(
        renderer.prepare(&call(
            &profile,
            json!({"radius_catalog_digest":"00","radius_model_id":"dynamic-model"})
        )),
        Err(RadiusRenderError::CatalogBindingMismatch)
    ));
}

#[test]
fn radius_payg_requires_explicit_selection_and_uses_bound_rates() {
    let catalog = RadiusCatalog::from_json_at(CATALOG, "https://radius.pi.dev").unwrap();
    let subscription = catalog
        .select("radius", "dynamic-model", "catalog-rev")
        .unwrap();
    let payg = catalog
        .select_with_accounting(
            "radius",
            "dynamic-model",
            "catalog-rev",
            RadiusAccounting::Payg,
        )
        .unwrap();
    assert_ne!(subscription.profile_digest(), payg.profile_digest());
    let usage = runne_provider::ProviderUsage::new(1_000_000, 1_000_000, 100_000, 0).unwrap();
    let quote = payg
        .price_terminal_usage(&payg.catalog_digest(), &payg.profile_digest(), usage)
        .unwrap();
    assert_eq!(quote.currency(), "USD");
    assert_eq!(quote.charge_micros(), 2_910_000);
    let zero = subscription
        .price_terminal_usage(
            &subscription.catalog_digest(),
            &subscription.profile_digest(),
            usage,
        )
        .unwrap();
    assert_eq!(zero.currency(), "XXX");
    assert_eq!(zero.charge_micros(), 0);
}

#[test]
fn radius_context_bound_reserves_protocol_overhead() {
    let catalog = RadiusCatalog::from_json(
        br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"small","name":"Small","reasoning":false,"input":["text"],"cost":{"input":1,"output":2,"cacheRead":0,"cacheWrite":0},"contextWindow":4096,"maxTokens":512}]}"#,
    )
    .unwrap();
    let profile = catalog.select("radius", "small", "revision").unwrap();
    assert_eq!(profile.max_input_tokens(), 3_584);
    assert_eq!(profile.max_input_bytes(), 3_328);
    let renderer = RadiusRenderer::new(profile.clone());
    let make_call = |size| {
        ProviderCall::new(
            ProviderCallId::from_bytes([7; 16]),
            ModelRef::new(
                ProviderId::new(profile.provider_id()).unwrap(),
                profile.model_id(),
                profile.revision(),
            )
            .unwrap(),
            [6; 32],
            16,
            renderer.binding_extension(),
        )
        .unwrap()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "x".repeat(size)).unwrap(),
        ])
        .unwrap()
        .with_required_capabilities(vec![ProviderCapability::Streaming])
    };
    assert!(renderer.prepare(&make_call(3_328)).is_ok());
    assert!(renderer.prepare(&make_call(3_329)).is_err());
}

#[test]
fn radius_payg_rejects_zero_rate_snapshot() {
    let catalog = RadiusCatalog::from_json(
        br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"free","name":"Free","reasoning":false,"input":["text"],"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0},"contextWindow":4096,"maxTokens":512}]}"#,
    )
    .unwrap();
    assert!(
        catalog
            .select_with_accounting("radius", "free", "revision", RadiusAccounting::Payg)
            .is_err()
    );
    let subscription = catalog.select("radius", "free", "revision").unwrap();
    let usage = runne_provider::ProviderUsage::new(1, 1, 0, 0).unwrap();
    let priced = subscription
        .price_terminal_usage(
            &subscription.catalog_digest(),
            &subscription.profile_digest(),
            usage,
        )
        .unwrap();
    assert_eq!((priced.charge_micros(), priced.currency()), (0, "XXX"));
}

#[test]
fn radius_lifecycle_rejects_altered_text_end_and_normalizes_usage() {
    let stream = concat!(
        "data: {\"type\":\"start\"}\n\n",
        "data: {\"type\":\"text_start\",\"contentIndex\":0}\n\n",
        "data: {\"type\":\"text_delta\",\"contentIndex\":0,\"delta\":\"hello\"}\n\n",
        "data: {\"type\":\"text_end\",\"contentIndex\":0,\"content\":\"hello\"}\n\n",
        "data: {\"type\":\"done\",\"reason\":\"stop\",\"usage\":{\"input\":10,\"output\":2,\"cacheRead\":3,\"cacheWrite\":1,\"totalTokens\":12}}\n\n",
    );
    let mut decoder = RadiusStreamDecoder::new();
    for fragment in stream.as_bytes().chunks(3) {
        decoder.push(fragment).unwrap();
    }
    let events = decoder.finish().unwrap();
    assert!(
        matches!(events[1].kind(), ProviderStreamEventKind::TextDelta { text } if text == "hello")
    );
    assert!(matches!(
        events.last().unwrap().kind(),
        ProviderStreamEventKind::Finished { .. }
    ));

    let bad = stream.replace("\"content\":\"hello\"", "\"content\":\"tampered\"");
    let mut decoder = RadiusStreamDecoder::new();
    assert_eq!(
        decoder.push(bad.as_bytes()),
        Err(RadiusStreamError::Malformed)
    );
}

#[test]
fn radius_large_valid_stream_is_chunk_boundary_equivalent() {
    let delta = "x".repeat(2_048);
    let content = delta.repeat(40);
    let mut stream = "data: {\"type\":\"start\"}\n\n".to_owned()
        + "data: {\"type\":\"text_start\",\"contentIndex\":0}\n\n";
    for _ in 0..40 {
        let _ = writeln!(
            stream,
            "data: {{\"type\":\"text_delta\",\"contentIndex\":0,\"delta\":\"{delta}\"}}\n"
        );
    }
    let _ = writeln!(
        stream,
        "data: {{\"type\":\"text_end\",\"contentIndex\":0,\"content\":\"{content}\"}}\n"
    );
    stream.push_str(
        "data: {\"type\":\"done\",\"reason\":\"stop\",\"usage\":{\"input\":10,\"output\":2,\"cacheRead\":3,\"cacheWrite\":1,\"totalTokens\":12}}\n\n",
    );

    let mut whole = RadiusStreamDecoder::new();
    whole.push(stream.as_bytes()).unwrap();
    let expected = whole.finish().unwrap();

    let mut chunked = RadiusStreamDecoder::new();
    for fragment in stream.as_bytes().chunks(97) {
        chunked.push(fragment).unwrap();
    }
    assert_eq!(chunked.finish().unwrap(), expected);
}

#[test]
fn radius_rejects_one_oversized_frame() {
    let oversized = "x".repeat(65_536);
    let stream = format!(
        "data: {{\"type\":\"start\"}}\n\ndata: {{\"type\":\"text_start\",\"contentIndex\":0}}\n\ndata: {{\"type\":\"text_delta\",\"contentIndex\":0,\"delta\":\"{oversized}\"}}\n\n"
    );
    let mut decoder = RadiusStreamDecoder::new();
    assert_eq!(
        decoder.push(stream.as_bytes()),
        Err(RadiusStreamError::BoundExceeded)
    );
}

#[test]
fn radius_rejects_http_catalog_and_tools() {
    let bad = br#"{"baseUrl":"http://radius.invalid","models":[]}"#;
    assert!(RadiusCatalog::from_json(bad).is_err());
    let substituted = br#"{"baseUrl":"https://attacker.invalid","models":[]}"#;
    assert!(RadiusCatalog::from_json(substituted).is_err());
    let injected = br#"{"baseUrl":"https://radius.pi.dev","apiKey":"leak","models":[]}"#;
    assert!(RadiusCatalog::from_json(injected).is_err());
    let tool =
        b"data: {\"type\":\"start\"}\n\ndata: {\"type\":\"toolcall_start\",\"contentIndex\":0}\n\n";
    let mut decoder = RadiusStreamDecoder::new();
    assert_eq!(
        decoder.push(tool),
        Err(RadiusStreamError::UnsupportedContent)
    );
}

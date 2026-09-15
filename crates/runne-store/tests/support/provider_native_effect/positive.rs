use super::*;
use runne_provider_native_wire::GeminiProfile;

fn gemini_profile() -> NativeWireProfile {
    NativeWireProfile::Gemini(
        GeminiProfile::new_with_accounting(
            "google",
            "gocode-native/gemini/1",
            "gemini-2.5-flash",
            "pi/revision",
            [11; 32],
            [12; 32],
            WireLimits::new(64, 65_536, 262_144, 8_192, 524_288, 16_384).unwrap(),
            NativeAccounting::Payg {
                input_micros_per_million: 1,
                output_micros_per_million: 2,
                cached_input_micros_per_million: 1,
                cache_write_micros_per_million: 1,
            },
        )
        .unwrap(),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_dispatches_gemini_payg_without_anthropic_headers() {
    let profile = gemini_profile();
    let fixture = fixture::fixture::fixture(
        "google",
        profile.model_id(),
        profile.model_revision(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        profile.call_binding_extension(),
        "USD",
        74,
    );
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        provider: "google".into(),
    });
    let transport = Arc::new(NativeFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::fixture::gemini_response(profile.model_id()),
        expected_url: format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:streamGenerateContent?alt=sse",
            profile.model_id()
        ),
        anthropic: false,
    });
    let effect = NativeEffect::new_with_transport(
        profile,
        TrustedNativeEndpoint::gemini("https://generativelanguage.googleapis.com/v1beta").unwrap(),
        NativeAuthDescriptor::GeminiApiKey,
        materializer.clone(),
        NativeEffectConfig::default(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    let outcome = coordinator.dispatch(fixture.request).await.unwrap();
    let binding = match outcome {
        ProviderCoordinatorOutcome::Streaming { binding } => binding,
        other => panic!("unexpected outcome: {other:?}"),
    };
    let kinds = collect_native(effect.as_ref(), binding.execution().stream_id()).await;
    assert_eq!(
        (
            materializer.calls.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    assert!(kinds.iter().any(
        |kind| matches!(kind, ProviderStreamEventKind::TextDelta { text } if text == "hello")
    ));
    assert!(kinds.iter().any(|kind| matches!(kind, ProviderStreamEventKind::Usage { usage } if usage.total_tokens() == 10)));
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ProviderStreamEventKind::Finished { .. }))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_dispatches_radius_payg_through_fake_http() {
    let profile = radius_profile();
    let renderer = runne_provider_radius::RadiusRenderer::new(profile.clone());
    let fixture = fixture::fixture::fixture(
        "radius",
        profile.model_id(),
        profile.revision(),
        profile.profile_digest(),
        profile.catalog_digest(),
        renderer.binding_extension(),
        "USD",
        75,
    );
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        provider: "radius".into(),
    });
    let transport = Arc::new(RadiusFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::fixture::radius_response(),
    });
    let effect = RadiusEffect::new_with_transport(
        profile,
        RadiusAuth::ApiKey,
        materializer.clone(),
        RadiusEffectConfig::default(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    let outcome = coordinator.dispatch(fixture.request).await.unwrap();
    let binding = match outcome {
        ProviderCoordinatorOutcome::Streaming { binding } => binding,
        other => panic!("unexpected outcome: {other:?}"),
    };
    let stream = binding.execution().stream_id();
    let mut cursor = runne_provider::StreamCursor::new(0);
    let mut kinds = Vec::new();
    while let Ok(item) = effect.next(&stream, cursor).await {
        kinds.push(item.event().kind().clone());
        cursor = runne_provider::StreamCursor::new(cursor.sequence() + 1);
    }
    assert_eq!(
        (
            materializer.calls.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
    assert!(kinds.iter().any(
        |kind| matches!(kind, ProviderStreamEventKind::TextDelta { text } if text == "hello")
    ));
    assert!(kinds.iter().any(|kind| matches!(kind, ProviderStreamEventKind::Usage { usage } if usage.total_tokens() == 10)));
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ProviderStreamEventKind::Finished { .. }))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_native_sse_is_uncertain_after_fake_http_boundary() {
    let profile = anthropic_profile();
    let fixture = fixture::fixture::fixture(
        "anthropic",
        profile.model_id(),
        profile.model_revision(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        profile.call_binding_extension(),
        "XXX",
        76,
    );
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        provider: "anthropic".into(),
    });
    let transport = Arc::new(NativeFakeTransport {
        calls: AtomicUsize::new(0),
        body: b"event: message_stop\ndata: {}\n\n".to_vec(),
        expected_url: "https://api.anthropic.com/v1/messages".into(),
        anthropic: true,
    });
    let effect = NativeEffect::new_with_transport(
        profile,
        TrustedNativeEndpoint::anthropic("https://api.anthropic.com").unwrap(),
        NativeAuthDescriptor::AnthropicApiKey,
        materializer.clone(),
        NativeEffectConfig::default(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    assert!(matches!(
        coordinator.dispatch(fixture.request).await,
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert_eq!(
        (
            materializer.calls.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_profile_binding_has_zero_materialization_and_http() {
    let profile = anthropic_profile();
    let fixture = fixture::fixture::fixture(
        "anthropic",
        profile.model_id(),
        profile.model_revision(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        profile.call_binding_extension(),
        "XXX",
        77,
    );
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        provider: "anthropic".into(),
    });
    let transport = Arc::new(NativeFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::fixture::anthropic_response(profile.model_id()),
        expected_url: "https://api.anthropic.com/v1/messages".into(),
        anthropic: true,
    });
    let effect = NativeEffect::new_with_transport(
        profile,
        TrustedNativeEndpoint::anthropic("https://api.anthropic.com").unwrap(),
        NativeAuthDescriptor::AnthropicApiKey,
        materializer.clone(),
        NativeEffectConfig::default(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    let mut request = fixture.request;
    request.profile_digest = [99; 32];
    assert!(coordinator.dispatch(request).await.is_err());
    assert_eq!(
        (
            materializer.calls.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (0, 0)
    );
}

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use fixture::support::{Materializer, NativeFakeTransport, RadiusFakeTransport};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_daemon_native_effect::{
    NativeAuthDescriptor, NativeEffect, NativeEffectConfig, TrustedNativeEndpoint,
};
use runne_daemon_radius_effect::{RadiusAuth, RadiusEffect, RadiusEffectConfig};
use runne_provider::{ProviderPort, ProviderStreamEventKind, TextProviderProfile};
use runne_provider_native_wire::{
    AnthropicMessagesProfile, NativeAccounting, NativeWireProfile, WireLimits,
};
use runne_provider_radius::{RadiusAccounting, RadiusCatalog};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
};

#[path = "support/provider_native_effect/mod.rs"]
mod fixture;
#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/provider_native_effect/positive.rs"]
mod positive;
#[path = "support/provider_taskrun_start.rs"]
mod provider_taskrun_start;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

struct DenyingMaterializer {
    reads: AtomicUsize,
}
impl ProviderCredentialDispatchMaterializer for DenyingMaterializer {
    fn materialize_active(
        &self,
        _: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(SecureStoreError::CredentialAccessDenied)
    }
}

fn anthropic_profile() -> NativeWireProfile {
    NativeWireProfile::Anthropic(
        AnthropicMessagesProfile::new_with_accounting(
            "anthropic",
            "gocode-native/anthropic/1",
            "claude-sonnet",
            "pi/revision",
            [1; 32],
            [2; 32],
            WireLimits::new(64, 65_536, 262_144, 8_192, 524_288, 16_384).unwrap(),
            NativeAccounting::SubscriptionQuotaExternallyMetered,
        )
        .unwrap(),
    )
}

fn radius_profile() -> runne_provider_radius::RadiusProfile {
    let json = br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"fixture-model","name":"Fixture","reasoning":false,"input":["text"],"contextWindow":4096,"maxTokens":512,"cost":{"input":0.000001,"output":0.000002,"cacheRead":0.000001,"cacheWrite":0.000001}}]}"#;
    RadiusCatalog::from_json(json)
        .unwrap()
        .select_with_accounting(
            "radius",
            "fixture-model",
            "pi/revision",
            RadiusAccounting::Payg,
        )
        .unwrap()
}

async fn collect_native(
    effect: &NativeEffect,
    stream: runne_provider::ProviderStreamId,
) -> Vec<ProviderStreamEventKind> {
    let mut cursor = runne_provider::StreamCursor::new(0);
    let mut kinds = Vec::new();
    while let Ok(item) = effect.next(&stream, cursor).await {
        kinds.push(item.event().kind().clone());
        cursor = runne_provider::StreamCursor::new(cursor.sequence() + 1);
    }
    kinds
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_dispatches_anthropic_subscription_through_fake_http() {
    let profile = anthropic_profile();
    let fixture = fixture::support::fixture(
        "anthropic",
        profile.model_id(),
        profile.model_revision(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        profile.call_binding_extension(),
        "XXX",
        73,
    );
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        provider: "anthropic".into(),
    });
    let transport = Arc::new(NativeFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::support::anthropic_response(profile.model_id()),
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
async fn anthropic_subscription_receipt_denial_never_reaches_http() {
    let profile = anthropic_profile();
    let fixture = fixture::support::fixture(
        "anthropic",
        profile.model_id(),
        profile.model_revision(),
        profile.profile_digest(),
        profile.pricing_revision_digest(),
        profile.call_binding_extension(),
        "XXX",
        71,
    );
    let materializer = Arc::new(DenyingMaterializer {
        reads: AtomicUsize::new(0),
    });
    let transport = Arc::new(NativeFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::support::anthropic_response(profile.model_id()),
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
            materializer.reads.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (1, 0)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn radius_payg_receipt_denial_never_reaches_http() {
    let profile = radius_profile();
    let renderer = runne_provider_radius::RadiusRenderer::new(profile.clone());
    let fixture = fixture::support::fixture(
        "radius",
        profile.model_id(),
        profile.revision(),
        profile.profile_digest(),
        profile.catalog_digest(),
        renderer.binding_extension(),
        "USD",
        72,
    );
    let materializer = Arc::new(DenyingMaterializer {
        reads: AtomicUsize::new(0),
    });
    let transport = Arc::new(RadiusFakeTransport {
        calls: AtomicUsize::new(0),
        body: fixture::support::radius_response(),
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
    assert!(matches!(
        coordinator.dispatch(fixture.request).await,
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert_eq!(
        (
            materializer.reads.load(Ordering::SeqCst),
            transport.calls.load(Ordering::SeqCst)
        ),
        (1, 0)
    );
}

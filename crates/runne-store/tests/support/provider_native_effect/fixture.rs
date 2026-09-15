use std::sync::atomic::{AtomicUsize, Ordering};

use runne_application::provider::ProviderCoordinatorRequest;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::ProviderFuture;
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput,
};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};
use serde_json::Value;

pub struct Fixture {
    pub(crate) _database: crate::validated_reopen::ProviderTestDatabase,
    pub(crate) dispatch: SqliteProviderDispatchStore,
    pub(crate) execution: SqliteProviderExecutionStore,
    pub(crate) credential: SqliteProviderCredentialLifecycleStore,
    pub(crate) launch: runne_store::provider::ProviderRuntimeLaunchCapability,
    pub(crate) request: ProviderCoordinatorRequest,
}

pub(crate) fn fixture(
    provider: &str,
    model: &str,
    revision: &str,
    profile_digest: [u8; 32],
    pricing_digest: [u8; 32],
    extension: Value,
    currency: &str,
    discriminator: u8,
) -> Fixture {
    let database = crate::validated_reopen::ProviderTestDatabase::new("native-effect");
    let dispatch = database.dispatch();
    let execution = database.execution();
    let credential =
        crate::online_credential_fixture::credential(&database, provider, discriminator);
    let launch = execution
        .activate_runtime_launch(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 1,
            principal_id: "principal".into(),
            owner_id: "owner".into(),
            scope: "provider.dispatch".into(),
            generation: 1,
            fencing_token: 1,
            capability_grant_id: "grant".into(),
            capability_revision: 1,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval".into(),
            approval_revision: 1,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest,
            pricing_revision_digest: pricing_digest,
            activation_binding_kind:
                runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    crate::online_proof::arm(&execution, 1);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([41; 16]),
        ModelRef::new(ProviderId::new(provider).unwrap(), model, revision).unwrap(),
        [5; 32],
        64,
        extension,
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    Fixture {
        _database: database,
        dispatch,
        execution,
        credential,
        launch,
        request: ProviderCoordinatorRequest {
            call,
            principal_id: "principal".into(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            profile_digest,
            pricing_revision_digest: pricing_digest,
            requested_input_tokens: 32,
            requested_output_tokens: 64,
            max_cost_micros: 10_000,
            currency: currency.into(),
            provider_idempotency_key: format!("native-effect-{provider}"),
        },
    }
}

pub(crate) struct Materializer {
    pub(crate) calls: AtomicUsize,
    pub(crate) provider: String,
}

impl ProviderCredentialDispatchMaterializer for Materializer {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            read.capability().version_ref().provider().as_str(),
            self.provider
        );
        ProviderCredentialMaterial::new(b"fixture-secret".to_vec())
    }
}

pub(crate) struct NativeFakeTransport {
    pub(crate) calls: AtomicUsize,
    pub(crate) body: Vec<u8>,
    pub(crate) expected_url: String,
    pub(crate) anthropic: bool,
}

impl runne_daemon_native_effect::NativeTransport for NativeFakeTransport {
    fn send(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
        _: Vec<u8>,
    ) -> ProviderFuture<
        '_,
        Result<
            runne_daemon_native_effect::NativeTransportResponse,
            runne_daemon_native_effect::NativeTransportError,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let credential_header = if self.anthropic {
            "x-api-key"
        } else {
            "x-goog-api-key"
        };
        let credential_ok = headers
            .get(credential_header)
            .is_some_and(|v| v.is_sensitive());
        let version_ok = headers
            .get("anthropic-version")
            .is_some_and(|v| v.to_str().ok() == Some("2023-06-01"));
        let valid = url == self.expected_url && credential_ok && (version_ok == self.anthropic);
        let body = self.body.clone();
        Box::pin(async move {
            Ok(runne_daemon_native_effect::NativeTransportResponse {
                url,
                status: if valid { 200 } else { 401 },
                content_type: Some("text/event-stream".into()),
                body,
            })
        })
    }
}

pub(crate) struct RadiusFakeTransport {
    pub(crate) calls: AtomicUsize,
    pub(crate) body: Vec<u8>,
}

impl runne_daemon_radius_effect::RadiusTransport for RadiusFakeTransport {
    fn send(
        &self,
        url: String,
        headers: reqwest::header::HeaderMap,
        _: Vec<u8>,
    ) -> ProviderFuture<
        '_,
        Result<
            runne_daemon_radius_effect::RadiusTransportResponse,
            runne_daemon_radius_effect::RadiusTransportError,
        >,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let valid = url == "https://radius.pi.dev/messages"
            && headers
                .get("authorization")
                .is_some_and(|v| v.is_sensitive());
        let body = self.body.clone();
        Box::pin(async move {
            Ok(runne_daemon_radius_effect::RadiusTransportResponse {
                url,
                status: if valid { 200 } else { 401 },
                content_type: Some("text/event-stream".into()),
                body,
            })
        })
    }
}

pub(crate) fn anthropic_response(model: &str) -> Vec<u8> {
    format!("event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"type\":\"message\",\"id\":\"m1\",\"role\":\"assistant\",\"model\":\"{model}\",\"usage\":{{\"input_tokens\":7,\"output_tokens\":0}}}}}}\n\nevent: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"hello\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"input_tokens\":7,\"output_tokens\":3}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n").into_bytes()
}

pub(crate) fn gemini_response(model: &str) -> Vec<u8> {
    format!("data: {{\"responseId\":\"g1\",\"modelVersion\":\"{model}\",\"candidates\":[{{\"index\":0,\"content\":{{\"parts\":[{{\"text\":\"hello\"}}]}}}}]}}\n\ndata: {{\"responseId\":\"g1\",\"modelVersion\":\"{model}\",\"candidates\":[{{\"index\":0,\"content\":{{\"parts\":[]}},\"finishReason\":\"STOP\"}}],\"usageMetadata\":{{\"promptTokenCount\":7,\"candidatesTokenCount\":3,\"totalTokenCount\":10}}}}\n\n").into_bytes()
}

pub(crate) fn radius_response() -> Vec<u8> {
    br#"data: {"type":"start"}
data: {"type":"text_start","contentIndex":0}
data: {"type":"text_delta","contentIndex":0,"delta":"hello"}
data: {"type":"text_end","contentIndex":0,"content":"hello"}
data: {"type":"done","reason":"stop","usage":{"input":7,"output":3,"cacheRead":0,"totalTokens":10}}
"#
    .to_vec()
}

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::redundant_pub_crate
)]

//! Provider-neutral native Anthropic/Gemini effect boundary.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::HeaderName;
use runne_provider::{ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId};
use runne_provider_native_wire::NativeWireProfile;
use runne_provider_quota::{QuotaEvidenceSink, SubscriptionBudgetAuthority};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use tokio::sync::Semaphore;

mod credentials;
mod port;
mod routes;
mod transport;
pub use transport::{
    NativeTransport, NativeTransportError, NativeTransportResponse, ReqwestNativeTransport,
};

const REQUEST_ID: HeaderName = HeaderName::from_static("x-client-request-id");
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_CHUNKS: usize = 32_768;

/// Authentication form selected by trusted composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuthDescriptor {
    /// Anthropic's `x-api-key` plus its required version header.
    AnthropicApiKey,
    /// A documented bearer header used by compatible gateways and Kimi/MiniMax.
    Bearer,
    /// Gemini's `x-goog-api-key` header; never a URL query parameter.
    GeminiApiKey,
    /// Vertex AI's bearer header.
    VertexBearer,
}

/// Exact typed route descriptor. The renderer cannot select or alter it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedNativeEndpoint {
    /// Base origin/prefix followed by the fixed `/v1/messages` suffix.
    Anthropic {
        /// Trusted HTTPS origin and optional path prefix.
        base_url: String,
    },
    /// Base origin/prefix followed by the fixed Gemini model method path.
    Gemini {
        /// Trusted HTTPS origin and optional path prefix.
        base_url: String,
    },
    /// Vertex route with trusted, validated project and location segments.
    Vertex {
        /// Trusted HTTPS origin and optional path prefix.
        base_url: String,
        /// Exact Google Cloud project segment.
        project: String,
        /// Exact Google Cloud location segment.
        location: String,
    },
}

/// Effect timing and concurrency limits.
#[derive(Debug, Clone, Copy)]
pub struct NativeEffectConfig {
    /// Timeout while waiting for response headers.
    pub header_timeout: Duration,
    /// Timeout between response body chunks.
    pub idle_timeout: Duration,
    /// Maximum concurrent network effects.
    pub max_concurrent: usize,
}

impl Default for NativeEffectConfig {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(30),
            max_concurrent: 8,
        }
    }
}

/// Constructor/validation failure before any external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeEffectError {
    /// The route is not a fixed HTTPS origin/prefix.
    #[error("native endpoint is not a safe HTTPS route")]
    UnsafeEndpoint,
    /// The auth form does not match the wire protocol.
    #[error("native auth descriptor does not match the profile")]
    AuthMismatch,
    /// A route segment or limit is invalid.
    #[error("native effect descriptor is invalid")]
    InvalidDescriptor,
}

impl TrustedNativeEndpoint {
    /// Validates a fixed HTTPS route before profile-specific allowlisting.
    pub fn anthropic(base_url: impl Into<String>) -> Result<Self, NativeEffectError> {
        Ok(Self::Anthropic {
            base_url: routes::safe_base(&base_url.into())?,
        })
    }
    /// Validates a fixed HTTPS Gemini route prefix.
    pub fn gemini(base_url: impl Into<String>) -> Result<Self, NativeEffectError> {
        Ok(Self::Gemini {
            base_url: routes::safe_base(&base_url.into())?,
        })
    }
    /// Validates a Vertex route and its exact project/location path inputs.
    pub fn vertex(
        base_url: impl Into<String>,
        project: impl Into<String>,
        location: impl Into<String>,
    ) -> Result<Self, NativeEffectError> {
        Ok(Self::Vertex {
            base_url: routes::safe_base(&base_url.into())?,
            project: routes::route_segment(&project.into())?,
            location: routes::route_segment(&location.into())?,
        })
    }
}

/// Native provider effect with credential-free prepare and receipt-gated dispatch.
pub struct NativeEffect {
    pub(crate) profile: NativeWireProfile,
    pub(crate) endpoint: TrustedNativeEndpoint,
    pub(crate) auth: NativeAuthDescriptor,
    pub(crate) materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    pub(crate) quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    pub(crate) budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    pub(crate) transport: Arc<dyn NativeTransport>,
    pub(crate) config: NativeEffectConfig,
    pub(crate) permits: Arc<Semaphore>,
    pub(crate) streams: Mutex<BTreeMap<ProviderStreamId, StreamEntry>>,
}

pub(crate) struct StreamEntry {
    pub(crate) events: VecDeque<ProviderStreamEvent>,
    pub(crate) _permit: tokio::sync::OwnedSemaphorePermit,
}

pub(crate) const fn is_terminal(event: &ProviderStreamEvent) -> bool {
    matches!(
        event.kind(),
        ProviderStreamEventKind::Finished { .. } | ProviderStreamEventKind::ScannerCompleted { .. }
    )
}

impl NativeEffect {
    /// Constructs the production effect with redirects, retries, and proxy fallback disabled.
    pub fn new(
        profile: NativeWireProfile,
        endpoint: TrustedNativeEndpoint,
        auth: NativeAuthDescriptor,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: NativeEffectConfig,
    ) -> Result<Arc<Self>, NativeEffectError> {
        Self::new_with_quota(profile, endpoint, auth, materializer, config, None)
    }

    /// Constructs a native effect with shared provider-neutral quota evidence.
    pub fn new_with_quota(
        profile: NativeWireProfile,
        endpoint: TrustedNativeEndpoint,
        auth: NativeAuthDescriptor,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: NativeEffectConfig,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    ) -> Result<Arc<Self>, NativeEffectError> {
        Self::new_with_quota_and_budget(
            profile,
            endpoint,
            auth,
            materializer,
            config,
            quota_sink,
            None,
        )
    }

    /// Constructs a native effect with quota evidence and durable subscription accounting.
    pub fn new_with_quota_and_budget(
        profile: NativeWireProfile,
        endpoint: TrustedNativeEndpoint,
        auth: NativeAuthDescriptor,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: NativeEffectConfig,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Result<Arc<Self>, NativeEffectError> {
        transport::build(NativeEffectArgs {
            profile,
            endpoint,
            auth,
            materializer,
            transport: Arc::new(
                ReqwestNativeTransport::new(config.idle_timeout)
                    .map_err(|_| NativeEffectError::InvalidDescriptor)?,
            ),
            config,
            quota_sink,
            budget,
        })
    }

    /// Constructs an effect with a caller-supplied bounded transport seam.
    pub fn new_with_transport(
        profile: NativeWireProfile,
        endpoint: TrustedNativeEndpoint,
        auth: NativeAuthDescriptor,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: NativeEffectConfig,
        transport: Arc<dyn NativeTransport>,
    ) -> Result<Arc<Self>, NativeEffectError> {
        transport::build(NativeEffectArgs {
            profile,
            endpoint,
            auth,
            materializer,
            transport,
            config,
            quota_sink: None,
            budget: None,
        })
    }

    /// Creates an effect with an injected reqwest client for in-crate tests.
    #[cfg(test)]
    pub fn with_client(
        profile: NativeWireProfile,
        endpoint: TrustedNativeEndpoint,
        auth: NativeAuthDescriptor,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        client: reqwest::Client,
        config: NativeEffectConfig,
    ) -> Result<Arc<Self>, NativeEffectError> {
        transport::build(NativeEffectArgs {
            profile,
            endpoint,
            auth,
            materializer,
            transport: Arc::new(ReqwestNativeTransport::from_client(
                client,
                config.idle_timeout,
            )),
            config,
            quota_sink: None,
            budget: None,
        })
    }
}

pub(crate) struct NativeEffectArgs {
    pub(crate) profile: NativeWireProfile,
    pub(crate) endpoint: TrustedNativeEndpoint,
    pub(crate) auth: NativeAuthDescriptor,
    pub(crate) materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    pub(crate) quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    pub(crate) budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    pub(crate) transport: Arc<dyn NativeTransport>,
    pub(crate) config: NativeEffectConfig,
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

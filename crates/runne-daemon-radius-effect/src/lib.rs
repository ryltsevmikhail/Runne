#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

//! Receipt-gated Radius `pi-messages` provider effect.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_provider::{ProviderStreamEvent, ProviderStreamId};
use runne_provider_quota::{QuotaEvidenceSink, SubscriptionBudgetAuthority};
use runne_provider_radius::{RadiusProfile, RadiusRenderer};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use tokio::sync::Semaphore;

mod credentials;
mod port;
mod transport;
pub use transport::{
    RadiusTransport, RadiusTransportError, RadiusTransportResponse, ReqwestRadiusTransport,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_CHUNKS: usize = 32_768;

/// The only initial Radius authentication form admitted by this effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadiusAuth {
    /// API key sent as an exact bearer header.
    ApiKey,
}

/// Effect timing and concurrency limits.
#[derive(Debug, Clone, Copy)]
pub struct RadiusEffectConfig {
    /// Timeout while waiting for response headers.
    pub header_timeout: Duration,
    /// Timeout between response body chunks.
    pub idle_timeout: Duration,
    /// Maximum active network effects and retained streams.
    pub max_concurrent: usize,
}

impl Default for RadiusEffectConfig {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(30),
            max_concurrent: 8,
        }
    }
}

/// Radius effect construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RadiusEffectError {
    /// The profile is not bound to the official Radius gateway.
    #[error("Radius profile is not bound to the official gateway")]
    InvalidProfile,
    /// The effect descriptor or production client is invalid.
    #[error("Radius effect descriptor is invalid")]
    InvalidDescriptor,
}

/// Receipt-gated Radius effect with no OAuth or caller-selected endpoint.
pub struct RadiusEffect {
    pub(crate) profile: RadiusProfile,
    pub(crate) renderer: RadiusRenderer,
    pub(crate) auth: RadiusAuth,
    pub(crate) materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    pub(crate) quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    pub(crate) budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    pub(crate) transport: Arc<dyn RadiusTransport>,
    pub(crate) config: RadiusEffectConfig,
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
        runne_provider::ProviderStreamEventKind::Finished { .. }
            | runne_provider::ProviderStreamEventKind::ScannerCompleted { .. }
    )
}

impl RadiusEffect {
    /// Constructs the production Radius effect; the endpoint comes only from the validated profile.
    pub fn new(
        profile: RadiusProfile,
        auth: RadiusAuth,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: RadiusEffectConfig,
    ) -> Result<Arc<Self>, RadiusEffectError> {
        Self::new_with_quota(profile, auth, materializer, config, None)
    }

    /// Constructs a Radius effect with shared provider-neutral quota evidence.
    pub fn new_with_quota(
        profile: RadiusProfile,
        auth: RadiusAuth,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: RadiusEffectConfig,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    ) -> Result<Arc<Self>, RadiusEffectError> {
        Self::new_with_quota_and_budget(profile, auth, materializer, config, quota_sink, None)
    }

    /// Constructs a Radius effect with durable subscription accounting.
    pub fn new_with_quota_and_budget(
        profile: RadiusProfile,
        auth: RadiusAuth,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: RadiusEffectConfig,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Result<Arc<Self>, RadiusEffectError> {
        transport::build(
            profile,
            auth,
            materializer,
            config,
            Arc::new(
                ReqwestRadiusTransport::new(config.idle_timeout)
                    .map_err(|_| RadiusEffectError::InvalidDescriptor)?,
            ),
            quota_sink,
            budget,
        )
    }

    /// Constructs an effect with a caller-supplied bounded transport seam.
    pub fn new_with_transport(
        profile: RadiusProfile,
        auth: RadiusAuth,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        config: RadiusEffectConfig,
        transport: Arc<dyn RadiusTransport>,
    ) -> Result<Arc<Self>, RadiusEffectError> {
        transport::build(profile, auth, materializer, config, transport, None, None)
    }
}

pub(crate) struct Ready {
    pub(crate) request: runne_provider::DispatchRequest,
    pub(crate) credential: runne_store::provider::CredentialDispatchBinding,
}

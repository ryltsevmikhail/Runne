//! Workspace-internal Local Engine provider effect boundary.
//!
//! Credential-free deterministic compatibility execution for the Local
//! Engine routing mode (Plan Task 13): the effect starts only through
//! the durable effect CAS (stage → receipt → dispatch), produces a
//! bounded deterministic response with no network and no external
//! secret, and never substitutes another backend. The native llama.cpp
//! bridge lands with its own qualification (Phase 6B); this boundary
//! fixes the routing contract and its tests.

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use runne_provider::{
    DispatchError, DispatchRequest, PrepareError, PreparedRequest, ProviderCall,
    ProviderCallDigestVersion, ProviderPort, ProviderStreamId,
};
use runne_store::provider::{ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect};

mod engine;
pub mod profile;
pub use profile::LocalEngineTextProfile;
mod port_impl;
#[cfg(test)]
mod tests;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Sender {}
}

/// Internal local provider boundary; downstream crates cannot implement
/// this trait.
pub trait LocalEngineEffect: sealed::Sealed + ProviderPort + ProviderEffectPort {}

impl<T: sealed::Sealed + ProviderPort + ProviderEffectPort> LocalEngineEffect for T {}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("local engine effect is unavailable")]
pub struct LocalEngineEffectError;

pub(crate) struct Sender {
    streams: Mutex<BTreeMap<ProviderStreamId, VecDeque<runne_provider::ProviderStreamEvent>>>,
    #[cfg(feature = "test-support")]
    invocation_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl Sender {
    fn new() -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "test-support")]
            invocation_counter: None,
        }
    }

    pub(crate) fn store_events(
        &self,
        attempt: runne_provider::DispatchAttemptId,
        events: Vec<runne_provider::ProviderStreamEvent>,
    ) -> Result<ProviderStreamId, DispatchError> {
        let stream = ProviderStreamId::from_bytes(*attempt.as_bytes());
        self.streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?
            .insert(stream, VecDeque::from(events));
        Ok(stream)
    }
}

/// Creates the production local engine effect. Credential-free by
/// contract: the durable binding is verified by the effect CAS, and no
/// external secret material is read.
pub fn production() -> Result<Arc<dyn LocalEngineEffect>, LocalEngineEffectError> {
    Ok(Arc::new(Sender::new()))
}

/// Creates a test-only local effect that counts execution after final-send authority consumption.
#[cfg(feature = "test-support")]
pub fn test_effect_with_invocation_counter(
    counter: Arc<std::sync::atomic::AtomicUsize>,
) -> Result<Arc<dyn LocalEngineEffect>, LocalEngineEffectError> {
    Ok(Arc::new(Sender {
        streams: Mutex::new(BTreeMap::new()),
        invocation_counter: Some(counter),
    }))
}

/// Validates the call binding for the local routing mode and prepares
/// the credential-free canonical bytes.
pub(crate) fn prepare_call(call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
    if call.model_ref().provider_id().as_str() != "local" {
        return Err(PrepareError::Render(
            "local engine effect bound to provider `local`".into(),
        ));
    }
    PreparedRequest::from_call(call)
}

/// Reused by `ProviderPort::prepare_for_digest_version`: only the
/// canonical V2 digest is supported.
pub(crate) fn ensure_digest_version(
    version: ProviderCallDigestVersion,
) -> Result<(), PrepareError> {
    if version != ProviderCallDigestVersion::V2 {
        return Err(PrepareError::UnsupportedDigestVersion(version));
    }
    Ok(())
}

/// Opaque staged effect accepted only by this crate's executor.
pub(crate) struct Staged {
    pub(crate) request: DispatchRequest,
}

impl ProviderReadyEffect for Staged {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl Sender {
    pub(crate) fn dispatch_staged(
        &self,
        staged: Staged,
        mut receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(staged.request.claim()) {
            return Err(DispatchError::MaybeDispatched);
        }
        if std::time::Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        receipt
            .take_final_send_authority()
            .map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?
            .consume()
            .map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?;
        #[cfg(feature = "test-support")]
        if let Some(counter) = &self.invocation_counter {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let events = engine::deterministic_events()?;
        self.store_events(staged.request.attempt_id(), events)
    }
}

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use runne_api::ProviderCredentialBrokerHandoffWitness;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
    )
))]
use runne_api::ProviderCredentialBrokerTransferAuthority;
use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialIntentConsumptionProof,
};
#[cfg(unix)]
use runne_provider::CredentialOperationSnapshot;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_provider::CredentialOperationState;
use runne_provider::{
    CredentialBindingDigest, CredentialInstallationOwnerId, CredentialOperationId,
};

#[cfg(unix)]
use super::super::ProviderCredentialEffectAuthority;
use super::super::operation_handle::ProviderCredentialOperationHandleIssuer;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) mod recovery;
mod reservation;
pub(in crate::application::provider_credential_enrollment::broker) use reservation::PendingBrokerRendezvousBinding;
#[cfg(unix)]
use reservation::ReservedTransitionRendezvous;

#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
mod endpoint;
#[cfg(all(
    feature = "desktop-protected",
    any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
#[cfg_attr(
    not(any(test, all(target_os = "macos", target_arch = "aarch64"))),
    expect(
        unused_imports,
        reason = "awaiting-writer type is test-driven until the D1 Linux composition slice mounts it"
    )
)]
pub(crate) use endpoint::AwaitingVerifiedWriter;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) use endpoint::PendingBrokerEndpointHandoff;

#[cfg(all(
    feature = "desktop-protected",
    any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
use super::rendezvous::DaemonBrokerAuthority;
#[cfg(any(
    all(test, unix),
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::rendezvous::DaemonOwnedUnixBrokerRendezvous;

/// Process-local one-shot authority for fresh, durable prepared operations.
pub(crate) struct PendingBrokerRendezvousRegistry {
    entries: Arc<Mutex<BTreeMap<CredentialOperationId, PendingEntry>>>,
    #[cfg(unix)]
    reserved: Arc<Mutex<Option<ReservedTransitionRendezvous>>>,
    handles: ProviderCredentialOperationHandleIssuer,
}

impl Clone for PendingBrokerRendezvousRegistry {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            #[cfg(unix)]
            reserved: Arc::clone(&self.reserved),
            handles: self.handles.duplicate(),
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
const MAX_PENDING: usize = 64;

struct PendingEntry {
    binding: PendingBrokerRendezvousBinding,
    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    authority_witness: ProviderCredentialBrokerHandoffWitness,
    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    broker_transfer: Option<ProviderCredentialBrokerTransferAuthority>,
    #[cfg(any(
        all(test, unix),
        all(feature = "desktop-protected", target_os = "linux"),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    rendezvous: DaemonOwnedUnixBrokerRendezvous,
}

impl PendingBrokerRendezvousRegistry {
    #[must_use]
    pub(crate) fn new(handles: ProviderCredentialOperationHandleIssuer) -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(unix)]
            reserved: Arc::new(Mutex::new(None)),
            handles,
        }
    }

    /// Registers exactly one daemon-created rendezvous for a fresh durable operation.
    #[cfg(all(test, unix))]
    // Only the unix broker transport registers prepared operations.
    #[cfg(unix)]
    pub(crate) fn register(
        &self,
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let binding =
            PendingBrokerRendezvousBinding::new(operation, authority, proof, now_high_water)?;
        let lease = self
            .begin_gate(now_high_water)?
            .preflight(authority, proof)?;
        if lease.entries.contains_key(&binding.operation_id) {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        #[cfg(not(unix))]
        return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        lease.commit_snapshot(operation);
        Ok(())
    }

    /// Reports only an unexpired, process-local rendezvous entry.
    pub(crate) fn has_live(
        &self,
        operation_id: CredentialOperationId,
        now_high_water: i64,
    ) -> bool {
        if now_high_water <= 0 {
            return false;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        clean_expired(&mut entries, now_high_water);
        entries.contains_key(&operation_id)
    }
}

fn clean_expired(entries: &mut BTreeMap<CredentialOperationId, PendingEntry>, now_high_water: i64) {
    entries.retain(|_, entry| !entry.binding.expired(now_high_water));
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;

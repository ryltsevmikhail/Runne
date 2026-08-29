use std::os::unix::net::UnixStream;

use runne_api::{
    ProviderCredentialBrokerKillRelinquishedProof, ProviderCredentialBrokerTransferAuthority,
};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

pub use runne_macos_process_identity::MacOsPeerKillReadyProof;

use super::ReceivedWriterProcessMeasurements;

/// Opaque exact peer kill capability captured from a daemon-owned Unix stream.
///
/// The native adapter retains the kernel audit token and PID privately. This
/// wrapper can only terminate the peer whose authenticated start tuple matched
/// at capture time.
pub struct MacOsPeerKillPending {
    inner: runne_macos_process_identity::MacOsPeerKillPending,
}

/// Kill-enabled peer capability minted only after authenticated relinquishment.
pub struct MacOsPeerKillCapability {
    inner: runne_macos_process_identity::MacOsPeerKillCapability,
}

/// Captures a kill capability for the exact writer peer on one daemon stream.
///
/// # Errors
///
/// Fails closed unless the kernel peer PID/start tuple matches authenticated
/// writer measurements and the runtime audit-token signal API is available.
pub fn capture_macos_daemon_peer_kill_capability(
    transport: &UnixStream,
    measurements: ReceivedWriterProcessMeasurements,
    authority: &ProviderCredentialBrokerTransferAuthority,
) -> Result<MacOsPeerKillPending, BrokerHandoffError> {
    capture(transport, measurements, authority, false)
}

impl MacOsPeerKillPending {
    /// Issues Ready only for the exact writer captured by this authority.
    ///
    /// # Errors
    ///
    /// Rejects another transfer authority or invalid captured state.
    pub fn issue_ready(
        &self,
        authority: &ProviderCredentialBrokerTransferAuthority,
    ) -> Result<MacOsPeerKillReadyProof, BrokerHandoffError> {
        self.inner.issue_ready(authority).map_err(map_native)
    }
    /// # Errors
    ///
    /// Rejects a proof from another transfer domain or authenticated tuple.
    pub fn enable_after_relinquished(
        self,
        authority: &ProviderCredentialBrokerTransferAuthority,
        proof: &ProviderCredentialBrokerKillRelinquishedProof,
    ) -> Result<MacOsPeerKillCapability, BrokerHandoffError> {
        self.inner
            .enable_after_relinquished(authority, proof)
            .map(|inner| MacOsPeerKillCapability { inner })
            .map_err(map_native)
    }
}

impl MacOsPeerKillCapability {
    /// Sends SIGKILL only to the captured, still-identical Unix peer.
    ///
    /// # Errors
    ///
    /// Fails closed on PID reuse, process replacement, or kernel rejection.
    pub fn terminate_exact_peer(self) -> Result<(), BrokerHandoffError> {
        self.inner
            .terminate_exact_peer()
            .map_err(|_| BrokerHandoffError::Rejected)
    }
}

impl std::fmt::Debug for MacOsPeerKillCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsPeerKillCapability(<daemon-owned-local-peer>)")
    }
}
impl std::fmt::Debug for MacOsPeerKillPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsPeerKillPending(<daemon-captured-disabled>)")
    }
}

fn capture(
    transport: &UnixStream,
    measurements: ReceivedWriterProcessMeasurements,
    authority: &ProviderCredentialBrokerTransferAuthority,
    missing_symbol: bool,
) -> Result<MacOsPeerKillPending, BrokerHandoffError> {
    #[cfg(test)]
    let capability = runne_macos_process_identity::test_only_capture_local_peer_kill_capability(
        transport,
        measurements.into_macos_peer_witness(),
        authority,
        !missing_symbol,
    );
    #[cfg(not(test))]
    let capability = {
        let _ = missing_symbol;
        runne_macos_process_identity::capture_local_peer_kill_capability(
            transport,
            measurements.into_macos_peer_witness(),
            authority,
        )
    };
    capability
        .map(|inner| MacOsPeerKillPending { inner })
        .map_err(map_native)
}

const fn map_native(error: runne_macos_process_identity::MacOsPeerKillError) -> BrokerHandoffError {
    match error {
        runne_macos_process_identity::MacOsPeerKillError::Rejected => BrokerHandoffError::Rejected,
        runne_macos_process_identity::MacOsPeerKillError::Unavailable => {
            BrokerHandoffError::Unavailable
        }
    }
}

#[cfg(test)]
pub(super) fn test_only_capture_without_runtime_symbol(
    transport: &UnixStream,
    measurements: ReceivedWriterProcessMeasurements,
    authority: &ProviderCredentialBrokerTransferAuthority,
) -> Result<MacOsPeerKillPending, BrokerHandoffError> {
    capture(transport, measurements, authority, true)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_observe_process_start(pid: u32) -> Result<[u8; 32], BrokerHandoffError> {
    let pid = std::num::NonZeroU32::new(pid).ok_or(BrokerHandoffError::Rejected)?;
    runne_macos_process_identity::MacOsProcessStartIdentity::observe(pid)
        .map(|identity| identity.digest())
        .map_err(|_| BrokerHandoffError::Rejected)
}

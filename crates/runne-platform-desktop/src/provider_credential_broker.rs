//! Desktop-owned broker handoff and exact child cleanup.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[cfg(unix)]
mod daemon_evidence;
#[cfg(unix)]
mod daemon_rendezvous;
#[cfg(unix)]
mod daemon_transport_offer;
pub(crate) mod handoff_trace;
#[cfg(any(test, not(target_os = "macos")))]
mod launch;
#[cfg(target_os = "macos")]
mod macos_daemon_kill;
#[cfg(target_os = "macos")]
mod macos_kill_exchange;
#[cfg(unix)]
mod macos_secret_pipe;
#[cfg(unix)]
mod macos_secret_sealer;
#[cfg(target_os = "macos")]
mod macos_writer_admission;
#[cfg(target_os = "macos")]
mod macos_writer_transfer;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
mod unix_daemon;
#[cfg(target_os = "macos")]
mod unix_daemon_macos;
#[cfg(unix)]
mod unix_descriptor;
mod writer_evidence;
#[cfg(all(target_os = "macos", feature = "test-support"))]
mod writer_stderr_log;
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, ProviderCredentialBrokerPort, WriterOwnership, WriterOwnershipState,
};

#[cfg(all(unix, feature = "test-support"))]
#[doc(hidden)]
pub use daemon_evidence::send_test_daemon_owned_writer_evidence;
#[cfg(target_os = "linux")]
pub use daemon_evidence::{
    LinuxWriterLiveFacts, LinuxWriterStartup, encode_linux_writer_startup_payload,
    linux_writer_self_measurements, receive_linux_writer_startup, respond_linux_writer_startup,
};
#[cfg(unix)]
pub use daemon_evidence::{
    ReceivedWriterProcessMeasurements, VerifiedWriterMeasurementFacts,
    receive_daemon_owned_writer_measurements,
};
#[cfg(unix)]
pub use daemon_rendezvous::{
    PreparedDaemonWriterEndpointHandoff, UnixReceivedDaemonWriterEndpoint,
    VerifiedDaemonWriterEndpointHandoffFacts, prepare_daemon_owned_writer_endpoint_handoff,
    receive_daemon_owned_writer_endpoint, send_daemon_owned_writer_endpoint,
};
#[cfg(unix)]
pub use daemon_transport_offer::{
    receive_daemon_control_transport_half, send_daemon_control_transport_half,
};
#[cfg(not(target_os = "macos"))]
pub use launch::writer_command;
#[cfg(all(target_os = "macos", feature = "test-support"))]
#[doc(hidden)]
pub use macos_daemon_kill::test_only_observe_process_start;
#[cfg(target_os = "macos")]
pub use macos_daemon_kill::{
    MacOsPeerKillCapability, MacOsPeerKillPending, MacOsPeerKillReadyProof,
    capture_macos_daemon_peer_kill_capability,
};
#[cfg(target_os = "macos")]
pub use macos_secret_pipe::MacOsAuthenticatedPairSecretRelay;
#[cfg(target_os = "linux")]
pub use macos_secret_pipe::MacOsAuthenticatedPairSecretRelay as LinuxAuthenticatedPairSecretRelay;
#[cfg(target_os = "macos")]
pub use macos_writer_admission::VerifiedMacOsWriterProcess;
#[cfg(target_os = "macos")]
pub use macos_writer_transfer::{
    MacOsWriterReapOnlyOwner, MacOsWriterRelinquishmentOutcome, MacOsWriterTransferPending,
};
#[cfg(unix)]
pub use unix::UnixRetainedWriterProcess;
#[cfg(all(
    target_os = "linux",
    any(
        feature = "test-support",
        feature = "linux-native-enrollment-qualification"
    )
))]
pub mod linux_native_enrollment_qualification;
#[cfg(unix)]
pub use unix::observe_current_process_start;
#[cfg(target_os = "linux")]
pub(crate) use unix_daemon::ValidatedLinuxSessionBusAddress;
#[cfg(target_os = "linux")]
pub use unix_daemon::linux_spawn::{
    spawn_linux_pair_writer_from_prepared_handoff, spawn_linux_writer_from_prepared_handoff,
    spawn_linux_writer_with_sockets,
};
#[cfg(all(unix, not(target_os = "macos")))]
pub use unix_daemon::spawn_unix_writer_from_prepared_daemon_handoff;
#[cfg(target_os = "macos")]
pub use unix_daemon::{
    spawn_macos_verified_pair_writer_from_prepared_daemon_handoff,
    spawn_macos_verified_writer_from_prepared_daemon_handoff,
};

#[cfg(all(test, target_os = "macos"))]
#[path = "provider_credential_broker/tests_macos_daemon_kill.rs"]
mod tests_macos_daemon_kill;
#[cfg(all(test, target_os = "macos"))]
#[path = "provider_credential_broker/tests_macos_writer_ownership.rs"]
mod tests_macos_writer_ownership;
#[cfg(all(test, target_os = "macos", feature = "test-support"))]
#[path = "provider_credential_broker/tests_writer_stderr_log.rs"]
mod tests_writer_stderr_log;

/// Non-serializable process evidence accepted only after platform validation.
pub struct WriterProcessEvidence {
    start: [u8; 32],
    image: [u8; 32],
    channel: [u8; 32],
    release_tuple: Option<[u8; 32]>,
    publication_public_key: Option<[u8; 32]>,
    writer_kill_public_key: Option<[u8; 32]>,
}

/// Exact desktop-held process operations. Implementations may only target the
/// retained child handle, never a PID lookup.
pub trait RetainedWriterProcess {
    /// Re-measures the exact retained child before its evidence is accepted.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the child no longer has its captured start identity.
    fn writer_start_identity(&self) -> Result<[u8; 32], BrokerHandoffError>;

    /// # Errors
    ///
    /// Returns a closed failure when the retained child cannot be terminated.
    fn terminate_retained_child(&mut self) -> Result<(), BrokerHandoffError>;

    /// # Errors
    ///
    /// Returns a closed failure when the retained child cannot be reaped.
    fn reap_retained_child(&mut self) -> Result<(), BrokerHandoffError>;
}

/// Owns Tauri's half of the broker handoff until daemon ACK and always owns wait/reap.
pub struct PlatformCredentialBroker<P> {
    process: P,
    evidence: WriterProcessEvidence,
    ownership: WriterOwnership,
}

impl<P: RetainedWriterProcess> PlatformCredentialBroker<P> {
    /// Creates a broker only with platform-validated endpoint/process evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when evidence is incomplete.
    pub fn new(process: P, evidence: WriterProcessEvidence) -> Result<Self, BrokerHandoffError> {
        if !evidence.is_complete() || process.writer_start_identity()? != evidence.start {
            return Err(BrokerHandoffError::Rejected);
        }
        Ok(Self {
            process,
            evidence,
            ownership: WriterOwnership::spawned(),
        })
    }

    #[must_use]
    pub const fn ownership_state(&self) -> WriterOwnershipState {
        self.ownership.state()
    }
}

impl<P: RetainedWriterProcess> ProviderCredentialBrokerPort for PlatformCredentialBroker<P> {
    /// # Errors
    ///
    /// Returns a closed failure if transfer was already started or evidence is invalid.
    fn transfer_to_daemon(&mut self) -> Result<(), BrokerHandoffError> {
        if !self.evidence.is_complete() {
            return Err(BrokerHandoffError::Rejected);
        }
        self.ownership.begin_transfer()
    }

    /// # Errors
    ///
    /// Returns a closed failure unless transfer is pending.
    fn acknowledge_daemon_kill_capability(&mut self) -> Result<(), BrokerHandoffError> {
        self.ownership.acknowledge_daemon_kill_capability()
    }

    /// # Errors
    ///
    /// Returns a closed failure after daemon kill capability acknowledgement.
    fn terminate_exact_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        if !self.ownership.tauri_may_kill() {
            return Err(BrokerHandoffError::Rejected);
        }
        self.process.terminate_retained_child()
    }

    /// # Errors
    ///
    /// Returns a closed failure if the retained child cannot be reaped or is already reaped.
    fn reap_exact_retained_child(&mut self) -> Result<(), BrokerHandoffError> {
        if self.ownership.state() == WriterOwnershipState::Reaped {
            return Err(BrokerHandoffError::Rejected);
        }
        self.process.reap_retained_child()?;
        self.ownership.reap()
    }
}

#[cfg(target_os = "linux")]
#[path = "provider_credential_broker/linux_writer_admission.rs"]
pub mod linux_writer_admission;

/// Platform-neutral re-export of the authenticated pair-secret sealer
/// (ring x25519+HKDF+ChaCha20-Poly1305, unchanged `GOCODE_CREDENTIAL_SECRET_*`
/// domains) so the Linux daemon broker channel reuses the exact macOS-sealed
/// relay construction instead of a parallel one.
#[cfg(unix)]
pub use macos_secret_sealer::AuthenticatedPairSecretSealer as UnixAuthenticatedPairSecretSealer;

#[cfg(test)]
#[path = "provider_credential_broker/tests_index.rs"]
mod tests_index;

//! Desktop-owned broker handoff and exact child cleanup.

#[cfg(unix)]
mod daemon_evidence;
#[cfg(unix)]
mod daemon_rendezvous;
#[cfg(any(test, not(target_os = "macos")))]
mod launch;
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

use std::fmt;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, ProviderCredentialBrokerPort, WriterOwnership, WriterOwnershipState,
};

#[cfg(unix)]
type DaemonHandoffDigests = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

#[cfg(all(unix, feature = "test-support"))]
#[doc(hidden)]
pub use daemon_evidence::send_test_daemon_owned_writer_evidence;
#[cfg(unix)]
pub use daemon_evidence::{
    ReceivedWriterProcessMeasurements, receive_daemon_owned_writer_measurements,
};
#[cfg(unix)]
pub use daemon_rendezvous::{
    PreparedDaemonWriterEndpointHandoff, UnixReceivedDaemonWriterEndpoint,
    prepare_daemon_owned_writer_endpoint_handoff, receive_daemon_owned_writer_endpoint,
    send_daemon_owned_writer_endpoint,
};
#[cfg(not(target_os = "macos"))]
pub use launch::writer_command;
#[cfg(target_os = "macos")]
pub use macos_writer_admission::VerifiedMacOsWriterProcess;
#[cfg(target_os = "macos")]
pub use macos_writer_transfer::MacOsWriterTransferPending;
#[cfg(unix)]
pub use unix::UnixRetainedWriterProcess;
#[cfg(target_os = "macos")]
pub use unix_daemon::spawn_macos_verified_writer_from_prepared_daemon_handoff;
#[cfg(all(unix, not(target_os = "macos")))]
pub use unix_daemon::spawn_unix_writer_from_prepared_daemon_handoff;

/// Non-serializable process evidence accepted only after platform validation.
pub struct WriterProcessEvidence {
    start: [u8; 32],
    image: [u8; 32],
    channel: [u8; 32],
    release_tuple: Option<[u8; 32]>,
    publication_public_key: Option<[u8; 32]>,
}

impl WriterProcessEvidence {
    #[cfg(target_os = "macos")]
    fn from_verified_macos_writer(
        start: [u8; 32],
        image: [u8; 32],
        release_tuple: [u8; 32],
        channel: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        Self::new_daemon_bound(start, image, release_tuple, channel, publication_public_key)
    }

    #[cfg(unix)]
    fn new_daemon_bound(
        start: [u8; 32],
        image: [u8; 32],
        release_tuple: [u8; 32],
        channel: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        let evidence = Self {
            start,
            image,
            channel,
            release_tuple: Some(release_tuple),
            publication_public_key: Some(publication_public_key),
        };
        evidence
            .is_daemon_bound()
            .then_some(evidence)
            .ok_or(BrokerHandoffError::Rejected)
    }

    #[cfg(test)]
    const fn test_only(
        start_identity: [u8; 32],
        image_identity: [u8; 32],
        channel_identity: [u8; 32],
    ) -> Self {
        Self {
            start: start_identity,
            image: image_identity,
            channel: channel_identity,
            release_tuple: None,
            publication_public_key: None,
        }
    }

    #[cfg(test)]
    const fn test_only_daemon(
        start_identity: [u8; 32],
        image_identity: [u8; 32],
        release_tuple_digest: [u8; 32],
        channel_identity: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Self {
        Self {
            start: start_identity,
            image: image_identity,
            channel: channel_identity,
            release_tuple: Some(release_tuple_digest),
            publication_public_key: Some(publication_public_key),
        }
    }
    fn is_complete(&self) -> bool {
        self.start != [0; 32] && self.image != [0; 32] && self.channel != [0; 32]
    }
    fn is_daemon_bound(&self) -> bool {
        self.is_complete()
            && self.release_tuple.is_some_and(|digest| digest != [0; 32])
            && self
                .publication_public_key
                .is_some_and(|public_key| public_key != [0; 32])
    }

    #[cfg(unix)]
    pub(crate) fn daemon_handoff_digests(&self) -> Option<DaemonHandoffDigests> {
        match (self.release_tuple, self.publication_public_key) {
            (Some(release_tuple), Some(publication_public_key)) if self.is_daemon_bound() => {
                Some((
                    self.start,
                    self.image,
                    release_tuple,
                    self.channel,
                    publication_public_key,
                ))
            }
            _ => None,
        }
    }

    /// Returns the fresh one-shot binding accepted by the native handoff.
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel
    }
}

impl fmt::Debug for WriterProcessEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WriterProcessEvidence(<native-only>)")
    }
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

#[cfg(test)]
mod tests;
#[cfg(test)]
#[path = "provider_credential_broker/tests_daemon_evidence.rs"]
mod tests_daemon_evidence;
#[cfg(test)]
#[path = "provider_credential_broker/tests_daemon_rendezvous.rs"]
mod tests_daemon_rendezvous;
#[cfg(test)]
#[path = "provider_credential_broker/tests_macos_descriptor_gate.rs"]
mod tests_macos_descriptor_gate;
#[cfg(test)]
#[path = "provider_credential_broker/tests_macos_writer_admission.rs"]
mod tests_macos_writer_admission;
#[cfg(test)]
#[path = "provider_credential_broker/tests_prepared_daemon_rendezvous.rs"]
mod tests_prepared_daemon_rendezvous;
#[cfg(test)]
#[path = "provider_credential_broker/tests_protocol_tags.rs"]
mod tests_protocol_tags;
#[cfg(test)]
#[path = "provider_credential_broker/tests_unix_descriptor.rs"]
mod tests_unix_descriptor;

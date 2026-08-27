//! Desktop-owned broker handoff and exact child cleanup.

mod launch;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
mod unix_transfer;

use std::fmt;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, ProviderCredentialBrokerPort, WriterOwnership, WriterOwnershipState,
};

pub use launch::writer_command;
#[cfg(unix)]
pub use unix::{
    UnixRetainedWriterProcess, UnixWriterBrokerEndpoints, configure_unix_writer_channels,
    spawn_unix_writer,
};
#[cfg(unix)]
pub use unix_transfer::{
    UnixReceivedWriterControl, receive_unix_writer_control, transfer_unix_writer_control,
};

/// Non-serializable process evidence accepted only after platform validation.
pub struct WriterProcessEvidence {
    start: [u8; 32],
    image: [u8; 32],
    channel: [u8; 32],
}

impl WriterProcessEvidence {
    #[cfg(unix)]
    pub(crate) fn from_native_writer(
        start: [u8; 32],
        image: [u8; 32],
        channel: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        let evidence = Self {
            start,
            image,
            channel,
        };
        evidence
            .is_complete()
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
        }
    }
    fn is_complete(&self) -> bool {
        self.start != [0; 32] && self.image != [0; 32] && self.channel != [0; 32]
    }

    pub(crate) const fn handoff_digests(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.start, self.image, self.channel)
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

//! Native-only writer artifact and broker handoff contracts.

mod launch;

use std::fmt;
use std::path::{Path, PathBuf};

pub use launch::VerifiedWriterLaunchSpec;

/// An immutable measured packaged `runne` artifact. Construction is restricted
/// to a verified bundle adapter (Task 15 in production).
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedWriterArtifact {
    executable: PathBuf,
    image_digest: [u8; 32],
    release_tuple_digest: [u8; 32],
}

impl VerifiedWriterArtifact {
    /// Creates a measured artifact for a verified immutable fixture or bundle.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the artifact is relative or unmeasured.
    pub fn new(
        executable: PathBuf,
        image_digest: [u8; 32],
        release_tuple_digest: [u8; 32],
    ) -> Result<Self, VerifiedWriterArtifactError> {
        if !executable.is_absolute() || image_digest == [0; 32] || release_tuple_digest == [0; 32] {
            return Err(VerifiedWriterArtifactError::Rejected);
        }
        Ok(Self {
            executable,
            image_digest,
            release_tuple_digest,
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    #[must_use]
    pub const fn image_digest(&self) -> [u8; 32] {
        self.image_digest
    }
    #[must_use]
    pub const fn release_tuple_digest(&self) -> [u8; 32] {
        self.release_tuple_digest
    }
}

impl fmt::Debug for VerifiedWriterArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedWriterArtifact(<measured>)")
    }
}

/// Source of exact writer artifacts. It must never resolve `PATH`.
pub trait VerifiedWriterArtifactPort {
    /// # Errors
    ///
    /// Returns a closed failure when no measured packaged writer is available.
    fn verified_writer(&self) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError>;
}

/// Closed writer artifact failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedWriterArtifactError {
    Rejected,
    Unavailable,
}

impl fmt::Display for VerifiedWriterArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("verified writer artifact unavailable")
    }
}

impl std::error::Error for VerifiedWriterArtifactError {}

/// Exact ownership states for one desktop-spawned writer child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterOwnershipState {
    SpawnedByTauri,
    TransferPending,
    DaemonKillCapabilityAcknowledged,
    Reaped,
}

/// Applies the only legal state progression. A rejected transition leaves
/// ownership unchanged, preventing duplicate transfer or double kill.
pub struct WriterOwnership {
    state: WriterOwnershipState,
}

impl WriterOwnership {
    #[must_use]
    pub const fn spawned() -> Self {
        Self {
            state: WriterOwnershipState::SpawnedByTauri,
        }
    }
    #[must_use]
    pub const fn state(&self) -> WriterOwnershipState {
        self.state
    }

    /// # Errors
    ///
    /// Returns a closed failure unless the writer was spawned by Tauri.
    pub fn begin_transfer(&mut self) -> Result<(), BrokerHandoffError> {
        self.transition(
            WriterOwnershipState::SpawnedByTauri,
            WriterOwnershipState::TransferPending,
        )
    }

    /// # Errors
    ///
    /// Returns a closed failure unless the transfer is pending.
    pub fn acknowledge_daemon_kill_capability(&mut self) -> Result<(), BrokerHandoffError> {
        self.transition(
            WriterOwnershipState::TransferPending,
            WriterOwnershipState::DaemonKillCapabilityAcknowledged,
        )
    }

    /// # Errors
    ///
    /// Returns a closed failure when the child was already reaped.
    pub const fn reap(&mut self) -> Result<(), BrokerHandoffError> {
        match self.state {
            WriterOwnershipState::SpawnedByTauri
            | WriterOwnershipState::TransferPending
            | WriterOwnershipState::DaemonKillCapabilityAcknowledged => {
                self.state = WriterOwnershipState::Reaped;
                Ok(())
            }
            WriterOwnershipState::Reaped => Err(BrokerHandoffError::Rejected),
        }
    }
    #[must_use]
    pub const fn tauri_may_kill(&self) -> bool {
        matches!(
            self.state,
            WriterOwnershipState::SpawnedByTauri | WriterOwnershipState::TransferPending
        )
    }
    #[must_use]
    pub fn daemon_may_kill(&self) -> bool {
        self.state == WriterOwnershipState::DaemonKillCapabilityAcknowledged
    }
    fn transition(
        &mut self,
        from: WriterOwnershipState,
        to: WriterOwnershipState,
    ) -> Result<(), BrokerHandoffError> {
        if self.state != from {
            return Err(BrokerHandoffError::Rejected);
        }
        self.state = to;
        Ok(())
    }
}

impl fmt::Debug for WriterOwnership {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WriterOwnership")
            .field("state", &self.state)
            .finish()
    }
}

/// Native adapter outcome for a connected endpoint plus retained child evidence.
/// The evidence remains adapter-owned and has no serializable handle value.
pub trait ProviderCredentialBrokerPort {
    /// # Errors
    ///
    /// Returns a closed failure when native endpoint transfer is unavailable or invalid.
    fn transfer_to_daemon(&mut self) -> Result<(), BrokerHandoffError>;

    /// # Errors
    ///
    /// Returns a closed failure unless the exact transfer is pending.
    fn acknowledge_daemon_kill_capability(&mut self) -> Result<(), BrokerHandoffError>;

    /// # Errors
    ///
    /// Returns a closed failure unless Tauri still owns the exact retained child.
    fn terminate_exact_retained_child(&mut self) -> Result<(), BrokerHandoffError>;

    /// # Errors
    ///
    /// Returns a closed failure when the exact retained child cannot be reaped.
    fn reap_exact_retained_child(&mut self) -> Result<(), BrokerHandoffError>;
}

/// Closed transfer/ownership failures. Native errors remain local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerHandoffError {
    Rejected,
    Unavailable,
}

impl fmt::Display for BrokerHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("provider credential broker handoff rejected")
    }
}

impl std::error::Error for BrokerHandoffError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_ownership_accepts_only_the_exact_handoff_order() {
        let mut ownership = WriterOwnership::spawned();
        assert!(ownership.tauri_may_kill());
        assert!(!ownership.daemon_may_kill());
        assert_eq!(
            ownership.acknowledge_daemon_kill_capability(),
            Err(BrokerHandoffError::Rejected)
        );
        ownership.begin_transfer().unwrap();
        ownership.acknowledge_daemon_kill_capability().unwrap();
        assert!(!ownership.tauri_may_kill());
        assert!(ownership.daemon_may_kill());
        ownership.reap().unwrap();
        assert_eq!(ownership.reap(), Err(BrokerHandoffError::Rejected));
    }

    #[test]
    fn artifact_rejects_relative_or_unmeasured_writer() {
        assert_eq!(
            VerifiedWriterArtifact::new(PathBuf::from("runne"), [1; 32], [2; 32]),
            Err(VerifiedWriterArtifactError::Rejected),
        );
    }

    #[test]
    fn writer_launch_spec_exposes_only_the_fixed_internal_mode_argument() {
        let artifact =
            VerifiedWriterArtifact::new(PathBuf::from("/bundle/runne"), [1; 32], [2; 32])
                .unwrap();

        let launch = VerifiedWriterLaunchSpec::new(artifact);

        assert_eq!(launch.executable(), Path::new("/bundle/runne"));
        assert_eq!(launch.arguments(), ["__provider-credential-broker-v1"]);
    }
}

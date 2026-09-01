//! Pair-only one-shot sealed credential input pipe.

use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

/// Pipe halves created only for a trusted Pair command before direct spawn.
pub(super) struct PreparedMacOsPairSecretPipe {
    reader: OwnedFd,
    writer: MacOsPairSecretWriter,
}

/// One-shot host-owned writer accepting only an already sealed envelope.
pub(super) struct MacOsPairSecretWriter(File);

/// One-shot Pair secret relay owned by the authenticated native rendezvous.
///
/// The renderer and Tauri orchestration never receive rendezvous key material,
/// a raw ticket, a verifier, or a reusable pipe writer.
pub struct MacOsAuthenticatedPairSecretRelay {
    sealer: super::macos_secret_sealer::AuthenticatedPairSecretSealer,
    writer: MacOsPairSecretWriter,
}

impl PreparedMacOsPairSecretPipe {
    /// Creates a close-on-exec pipe. Only the normalized read half is installed
    /// into the child; the write half remains host-owned.
    pub(super) fn prepare() -> Result<Self, BrokerHandoffError> {
        let (created_reader, created_writer) =
            rustix::pipe::pipe().map_err(|_| BrokerHandoffError::Unavailable)?;
        let reader = rustix::io::fcntl_dupfd_cloexec(&created_reader, 4)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
        let writer = rustix::io::fcntl_dupfd_cloexec(&created_writer, 4)
            .map_err(|_| BrokerHandoffError::Unavailable)?;
        Ok(Self {
            reader,
            writer: MacOsPairSecretWriter(File::from(writer)),
        })
    }

    pub(super) fn into_parts(self) -> (OwnedFd, MacOsPairSecretWriter) {
        (self.reader, self.writer)
    }
}

impl MacOsPairSecretWriter {
    /// Writes and closes exactly one typed sealed envelope.
    fn write_encoded(mut self, envelope: &[u8]) -> Result<(), BrokerHandoffError> {
        self.0
            .write_all(envelope)
            .map_err(|_| BrokerHandoffError::Unavailable)
    }
}

impl MacOsAuthenticatedPairSecretRelay {
    pub(super) const fn from_authenticated_parts(
        sealer: super::macos_secret_sealer::AuthenticatedPairSecretSealer,
        writer: MacOsPairSecretWriter,
    ) -> Self {
        Self { sealer, writer }
    }

    /// Verifies the daemon publication, seals the host-owned secret, and writes fd3 once.
    ///
    /// # Errors
    ///
    /// Returns a closed rejection for any wrong rendezvous, operation, attempt,
    /// publication, or envelope, and unavailable if the one-shot write fails.
    pub fn seal_and_write(
        self,
        frame: &[u8],
        credential: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), BrokerHandoffError> {
        let envelope = self.sealer.seal(frame, credential)?;
        self.writer.write_encoded(&envelope)
    }
}

impl std::fmt::Debug for PreparedMacOsPairSecretPipe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedMacOsPairSecretPipe(<native>)")
    }
}

impl std::fmt::Debug for MacOsPairSecretWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsPairSecretWriter(<one-shot>)")
    }
}

impl std::fmt::Debug for MacOsAuthenticatedPairSecretRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsAuthenticatedPairSecretRelay(<one-shot>)")
    }
}

#[cfg(test)]
pub(super) fn prepare_pair_secret_pipe() -> Result<PreparedMacOsPairSecretPipe, BrokerHandoffError>
{
    PreparedMacOsPairSecretPipe::prepare()
}

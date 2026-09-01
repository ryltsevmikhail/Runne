//! Opaque kernel-observed macOS process-start identities.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod continuous_clock;
mod ffi;
mod local_peer;
mod packaged_writer_observation;
mod peer_kill;
mod peer_kill_wire;
mod writer_bootstrap_transcript;
mod writer_endpoint_handoff;

#[cfg(test)]
#[path = "packaged_writer_observation_tests.rs"]
mod packaged_writer_observation_tests;

#[cfg(test)]
#[path = "writer_endpoint_handoff_tests.rs"]
mod writer_endpoint_handoff_tests;

pub use continuous_clock::{MacOsContinuousClock, MacOsContinuousClockError};
pub use local_peer::{MacOsLocalPeerProcessIdentity, MacOsLocalPeerProcessIdentityError};
pub use packaged_writer_observation::{
    MacOsPackagedWriterObservationError, MacOsPendingPackagedWriterObservationV1,
};
pub use peer_kill::{MacOsPeerKillCapability, MacOsPeerKillError};
pub use peer_kill_wire::MACOS_PEER_KILL_READY_WIRE_BYTES;
pub use writer_bootstrap_transcript::{
    MacOsPendingProvisionalReleaseMatchV1, MacOsPendingWriterBootstrapTranscriptV1,
};
pub use writer_endpoint_handoff::MacOsUntrustedWriterEndpointHandoffV1;

use std::fmt;
use std::fs::Metadata;
use std::num::NonZeroU32;
use std::path::Path;

/// Opaque digest of a kernel-observed macOS process start tuple.
#[derive(Eq, PartialEq)]
pub struct MacOsProcessStartIdentity([u8; 32]);

/// Captured native peer that remains unable to signal before relinquishment.
pub struct MacOsPeerKillPending {
    inner: MacOsPeerKillCapability,
    captured: runne_api::ProviderCredentialBrokerCapturedWriter,
}

/// Ready proof whose only constructor follows successful kernel peer capture.
///
/// ```compile_fail
/// let _ = runne_macos_process_identity::MacOsPeerKillReadyProof::new();
/// ```
pub struct MacOsPeerKillReadyProof {
    binding: runne_api::ProviderCredentialBrokerKillBindingV1,
    proof: [u8; 32],
}

impl MacOsProcessStartIdentity {
    /// Observes one live process through the macOS kernel process API.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure when the kernel cannot provide a complete,
    /// matching process-start tuple.
    pub fn observe(pid: NonZeroU32) -> Result<Self, MacOsProcessIdentityError> {
        ffi::observe(pid).map(Self)
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.0
    }
}

/// Captures only the exact peer in a daemon-authenticated writer witness.
///
/// # Errors
///
/// Fails closed for another authority domain, peer replacement, or unavailable
/// native audit-token signaling.
///
/// ```compile_fail
/// fn raw_capture_is_not_available<S: std::os::fd::AsFd>(
///     socket: &S,
///     start: [u8; 32],
///     authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
/// ) {
///     let _ = runne_macos_process_identity::capture_local_peer_kill_capability(
///         socket, &start, authority,
///     );
/// }
/// ```
pub fn capture_local_peer_kill_capability<S: std::os::fd::AsFd>(
    stream: &S,
    witness: runne_api::ProviderCredentialBrokerWriterEvidenceWitness,
    authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
) -> Result<MacOsPeerKillPending, MacOsPeerKillError> {
    let captured = authority
        .claim_writer_evidence(witness)
        .map_err(|_| MacOsPeerKillError::Rejected)?;
    let inner = peer_kill::capture(
        stream,
        captured.expected_process_start(),
        peer_kill::Resolver::Runtime,
    )?;
    Ok(MacOsPeerKillPending { inner, captured })
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_only_capture_local_peer_kill_capability<S: std::os::fd::AsFd>(
    stream: &S,
    witness: runne_api::ProviderCredentialBrokerWriterEvidenceWitness,
    authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
    resolve_signal: bool,
) -> Result<MacOsPeerKillPending, MacOsPeerKillError> {
    let captured = authority
        .claim_writer_evidence(witness)
        .map_err(|_| MacOsPeerKillError::Rejected)?;
    let inner = peer_kill::capture(
        stream,
        captured.expected_process_start(),
        peer_kill::Resolver::Test(resolve_signal),
    )?;
    Ok(MacOsPeerKillPending { inner, captured })
}

impl MacOsPeerKillPending {
    /// Issues Ready only for this authority's captured writer.
    ///
    /// # Errors
    ///
    /// Rejects another transfer authority or consumed writer evidence.
    pub fn issue_ready(
        &self,
        authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
    ) -> Result<MacOsPeerKillReadyProof, MacOsPeerKillError> {
        let proof = authority
            .authenticate_kill_ready_for_captured(&self.captured)
            .map_err(|_| MacOsPeerKillError::Rejected)?;
        Ok(MacOsPeerKillReadyProof {
            binding: self.captured.kill_binding(),
            proof,
        })
    }

    /// Enables signaling only after the captured writer signed relinquishment.
    ///
    /// # Errors
    ///
    /// Rejects a proof from another writer key, tuple, or transfer authority.
    pub fn enable_after_relinquished(
        self,
        authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
        proof: &runne_api::ProviderCredentialBrokerKillRelinquishedProof,
    ) -> Result<MacOsPeerKillCapability, MacOsPeerKillError> {
        authority
            .verifies_kill_relinquished_for_captured(proof, &self.captured)
            .then_some(self.inner)
            .ok_or(MacOsPeerKillError::Rejected)
    }

    /// Enables signaling only for a fixed relinquishment frame authenticated
    /// against this already-captured writer.
    ///
    /// # Errors
    ///
    /// Rejects malformed bytes, another writer tuple, or an invalid signature.
    pub fn enable_after_relinquished_wire(
        self,
        authority: &runne_api::ProviderCredentialBrokerTransferAuthority,
        wire: &[u8],
    ) -> Result<MacOsPeerKillCapability, MacOsPeerKillError> {
        let proof = authority
            .accept_kill_relinquished_wire_for_captured(wire, &self.captured)
            .map_err(|_| MacOsPeerKillError::Rejected)?;
        self.enable_after_relinquished(authority, &proof)
    }
}

impl MacOsPeerKillReadyProof {
    #[must_use]
    pub fn verifies(
        &self,
        authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
        binding: &runne_api::ProviderCredentialBrokerKillBindingV1,
    ) -> bool {
        self.binding == *binding
            && authenticator.verifies_kill_ready(&binding.ready_transcript(), &self.proof)
    }
}

impl std::fmt::Debug for MacOsPeerKillReadyProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacOsPeerKillReadyProof(<native-captured>)")
    }
}

/// Opaque vnode identity for the executable mapping of one live process.
#[derive(Eq, PartialEq)]
pub struct MacOsProcessExecutableIdentity(ffi::ExecutableVnodeIdentity);

impl MacOsProcessExecutableIdentity {
    /// Observes the executable VM mapping whose kernel path matches `path`.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure when no exact executable vnode is observable.
    pub fn observe(pid: NonZeroU32, path: &Path) -> Result<Self, MacOsProcessIdentityError> {
        ffi::observe_executable_vnode(pid, path).map(Self)
    }

    /// Matches the observed vnode to metadata from an already-open file.
    #[must_use]
    pub fn matches_file(&self, metadata: &Metadata) -> bool {
        self.0.matches_file(metadata)
    }
}

impl fmt::Debug for MacOsProcessExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsProcessExecutableIdentity(<kernel-observed>)")
    }
}

impl fmt::Debug for MacOsProcessStartIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsProcessStartIdentity(<kernel-observed>)")
    }
}

/// Opaque macOS kernel process-observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsProcessIdentityError;

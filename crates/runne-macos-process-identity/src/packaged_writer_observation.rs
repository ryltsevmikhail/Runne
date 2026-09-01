//! Low-level packaged writer and live-peer observation.

#![allow(
    clippy::redundant_pub_crate,
    reason = "crate-root tests exercise private observation layers"
)]

pub(super) mod artifact;
pub(super) mod package;
pub(super) mod process;
pub(super) mod security_code;

use package::PackagedWriterArtifacts;
use process::PackagedLiveProcessObservation;

use crate::{
    MacOsLocalPeerProcessIdentity, MacOsLocalPeerProcessIdentityError,
    MacOsUntrustedWriterEndpointHandoffV1,
};

/// Opaque native observation that grants no enrollment authority.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_fd<T: std::os::fd::AsFd>() {}
/// require_as_fd::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_as_raw_fd<T: std::os::fd::AsRawFd>() {}
/// require_as_raw_fd::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// fn require_into_raw_fd<T: std::os::fd::IntoRawFd>() {}
/// require_into_raw_fd::<runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1>();
/// ```
///
/// ```compile_fail
/// let _ = runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1 {};
/// ```
///
/// ```compile_fail
/// let _ = runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1::from_parts();
/// ```
///
/// ```compile_fail
/// fn raw(value: &runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1) {
///     let _ = value.path();
///     let _ = value.pid();
///     let _ = value.audit_token();
///     let _ = value.digest();
///     let _ = value.control();
///     let _ = value.root();
/// }
/// ```
///
/// ```compile_fail
/// fn authority(value: runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1) {
///     let _ = value.verify();
///     let _ = value.authenticate();
///     let _ = value.admit();
///     let _ = value.mint();
///     let _ = value.into_authority();
/// }
/// ```
#[doc(hidden)]
pub struct MacOsPendingPackagedWriterObservationV1 {
    _handoff: MacOsUntrustedWriterEndpointHandoffV1,
    _package: PackagedWriterArtifacts,
    _self_process: PackagedLiveProcessObservation,
    _peer_process: PackagedLiveProcessObservation,
    _peer: MacOsLocalPeerProcessIdentity,
}

/// Closed failure surface for native packaged-writer observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsPackagedWriterObservationError {
    Rejected,
    Unavailable,
}

impl MacOsUntrustedWriterEndpointHandoffV1 {
    /// Consumes the untrusted control handoff into a low-level native observation.
    ///
    /// # Errors
    ///
    /// Returns a closed error when native evidence is rejected or unavailable.
    #[doc(hidden)]
    pub fn observe_pending_packaged_writer(
        self,
    ) -> Result<MacOsPendingPackagedWriterObservationV1, MacOsPackagedWriterObservationError> {
        let self_code = security_code::NativeCodeObservation::capture_self()?;
        let package =
            PackagedWriterArtifacts::capture_from_writer_main(self_code.main_executable())?;
        let self_process = PackagedLiveProcessObservation::capture_self(&package, self_code)?;
        let peer = MacOsLocalPeerProcessIdentity::capture(self.observation_control())
            .map_err(map_peer_error)?;
        let peer_process = PackagedLiveProcessObservation::capture_peer(&package, &peer)?;

        package.revalidate()?;
        peer.revalidate_same_peer(self.observation_control())
            .map_err(map_peer_error)?;
        self_process.revalidate_self(&package)?;
        peer_process.revalidate_peer(&package, &peer)?;
        package.revalidate()?;
        peer.revalidate_same_peer(self.observation_control())
            .map_err(map_peer_error)?;

        Ok(MacOsPendingPackagedWriterObservationV1 {
            _handoff: self,
            _package: package,
            _self_process: self_process,
            _peer_process: peer_process,
            _peer: peer,
        })
    }
}

const fn map_peer_error(
    error: MacOsLocalPeerProcessIdentityError,
) -> MacOsPackagedWriterObservationError {
    match error {
        MacOsLocalPeerProcessIdentityError::Rejected => {
            MacOsPackagedWriterObservationError::Rejected
        }
        MacOsLocalPeerProcessIdentityError::Unavailable => {
            MacOsPackagedWriterObservationError::Unavailable
        }
    }
}

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

pub(super) struct CapturedPackagedWriterObservationV1 {
    package: PackagedWriterArtifacts,
    self_process: PackagedLiveProcessObservation,
    peer_process: PackagedLiveProcessObservation,
    peer: MacOsLocalPeerProcessIdentity,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum FinalRaceDrift {
    Package,
    Peer,
    Process,
    SecCode,
}

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
    _observation: CapturedPackagedWriterObservationV1,
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
        let observation = CapturedPackagedWriterObservationV1::capture_preserving_old_order(&self)?;
        Ok(MacOsPendingPackagedWriterObservationV1 {
            _handoff: self,
            _observation: observation,
        })
    }
}

impl CapturedPackagedWriterObservationV1 {
    fn capture_preserving_old_order(
        handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let (package, self_process) = capture_self_package()?;
        let peer = MacOsLocalPeerProcessIdentity::capture(handoff.observation_control())
            .map_err(map_peer_error)?;
        Self::complete(handoff, package, self_process, peer)
    }

    pub(super) fn capture_with_retained_peer(
        handoff: &MacOsUntrustedWriterEndpointHandoffV1,
        peer: MacOsLocalPeerProcessIdentity,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let (package, self_process) = capture_self_package()?;
        Self::complete(handoff, package, self_process, peer)
    }

    fn complete(
        handoff: &MacOsUntrustedWriterEndpointHandoffV1,
        package: PackagedWriterArtifacts,
        self_process: PackagedLiveProcessObservation,
        peer: MacOsLocalPeerProcessIdentity,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let peer_process = PackagedLiveProcessObservation::capture_peer(&package, &peer)?;
        (peer.process_start_digest() == peer_process.start_digest())
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;

        package.revalidate()?;
        peer.revalidate_same_peer(handoff.observation_control())
            .map_err(map_peer_error)?;
        self_process.revalidate_self(&package)?;
        peer_process.revalidate_peer(&package, &peer)?;
        package.revalidate()?;
        peer.revalidate_same_peer(handoff.observation_control())
            .map_err(map_peer_error)?;

        Ok(Self {
            package,
            self_process,
            peer_process,
            peer,
        })
    }

    pub(crate) const fn package(&self) -> &PackagedWriterArtifacts {
        &self.package
    }

    pub(crate) const fn self_process(&self) -> &PackagedLiveProcessObservation {
        &self.self_process
    }

    pub(crate) const fn peer_process(&self) -> &PackagedLiveProcessObservation {
        &self.peer_process
    }

    pub(crate) const fn peer(&self) -> &MacOsLocalPeerProcessIdentity {
        &self.peer
    }

    pub(crate) fn revalidate_for_provisional_session(
        &self,
        handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        let package = &self.package;
        let self_process = &self.self_process;
        let peer_process = &self.peer_process;
        let peer = &self.peer;
        peer.revalidate_same_peer(handoff.observation_control())
            .map_err(map_peer_error)?;
        package.revalidate()?;
        self_process.revalidate_self(package)?;
        peer_process.revalidate_peer(package, peer)?;
        peer.revalidate_same_peer(handoff.observation_control())
            .map_err(map_peer_error)
    }

    #[cfg(test)]
    pub(crate) fn test_only_inject_final_race(&mut self, race: FinalRaceDrift) {
        match race {
            FinalRaceDrift::Package => self.package.test_only_corrupt_writer_digest(),
            FinalRaceDrift::Peer => self.peer.test_only_corrupt_process_start(),
            FinalRaceDrift::Process => self.self_process.test_only_corrupt_start(),
            FinalRaceDrift::SecCode => self.self_process.test_only_corrupt_native_code(),
        }
    }
}

fn capture_self_package() -> Result<
    (PackagedWriterArtifacts, PackagedLiveProcessObservation),
    MacOsPackagedWriterObservationError,
> {
    #[cfg(test)]
    record_heavy_capture();
    let self_code = security_code::NativeCodeObservation::capture_self()?;
    let package = PackagedWriterArtifacts::capture_from_writer_main(self_code.main_executable())?;
    let self_process = PackagedLiveProcessObservation::capture_self(&package, self_code)?;
    Ok((package, self_process))
}

pub(super) const fn map_peer_error(
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

#[cfg(test)]
std::thread_local! {
    static HEAVY_CAPTURE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_heavy_capture() {
    HEAVY_CAPTURE_COUNT.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(crate) fn test_only_reset_heavy_capture_count() {
    HEAVY_CAPTURE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn test_only_heavy_capture_count() -> usize {
    HEAVY_CAPTURE_COUNT.with(std::cell::Cell::get)
}

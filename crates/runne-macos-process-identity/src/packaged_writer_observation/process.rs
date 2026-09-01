use std::num::NonZeroU32;

use super::MacOsPackagedWriterObservationError;
use super::package::{PackageRole, PackagedWriterArtifacts};
use super::security_code::NativeCodeObservation;
use crate::ffi::ExecutableVnodeIdentity;
use crate::{MacOsLocalPeerProcessIdentity, MacOsProcessStartIdentity};

pub(crate) struct PackagedLiveProcessObservation {
    pid: NonZeroU32,
    start: MacOsProcessStartIdentity,
    code: NativeCodeObservation,
    executable: ExecutableVnodeIdentity,
    role: PackageRole,
}

impl PackagedLiveProcessObservation {
    pub(super) fn capture_self(
        package: &PackagedWriterArtifacts,
        code: NativeCodeObservation,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let pid = NonZeroU32::new(std::process::id())
            .ok_or(MacOsPackagedWriterObservationError::Unavailable)?;
        Self::capture(pid, package, code, PackageRole::Writer)
    }

    pub(super) fn capture_peer(
        package: &PackagedWriterArtifacts,
        peer: &MacOsLocalPeerProcessIdentity,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        Self::capture(
            peer.pid(),
            package,
            NativeCodeObservation::capture_peer(peer)?,
            PackageRole::Daemon,
        )
    }

    fn capture(
        pid: NonZeroU32,
        package: &PackagedWriterArtifacts,
        code: NativeCodeObservation,
        role: PackageRole,
    ) -> Result<Self, MacOsPackagedWriterObservationError> {
        let start = observe_start(pid)?;
        package.require_main_locator(code.main_executable(), role)?;
        let executable = package.role(role).observe_executable_mapping(pid)?;
        (observe_start(pid)? == start)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        code.revalidate()?;
        Ok(Self {
            pid,
            start,
            code,
            executable,
            role,
        })
    }

    pub(super) fn revalidate_self(
        &self,
        package: &PackagedWriterArtifacts,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        let fresh = NativeCodeObservation::capture_self()?;
        self.revalidate(package, &fresh)
    }

    pub(super) fn revalidate_peer(
        &self,
        package: &PackagedWriterArtifacts,
        peer: &MacOsLocalPeerProcessIdentity,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        (peer.pid() == self.pid)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        let fresh = NativeCodeObservation::capture_peer(peer)?;
        self.revalidate(package, &fresh)
    }

    pub(crate) const fn start_digest(&self) -> [u8; 32] {
        self.start.digest()
    }

    pub(crate) const fn native_code(&self) -> &NativeCodeObservation {
        &self.code
    }

    #[cfg(test)]
    pub(crate) const fn test_only_corrupt_start(&mut self) {
        self.start.test_only_corrupt();
    }

    #[cfg(test)]
    pub(crate) fn test_only_corrupt_native_code(&mut self) {
        self.code.test_only_corrupt_main_executable();
    }

    fn revalidate(
        &self,
        package: &PackagedWriterArtifacts,
        fresh_code: &NativeCodeObservation,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        (observe_start(self.pid)? == self.start)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        self.code.matches_fresh(fresh_code)?;
        package.require_main_locator(fresh_code.main_executable(), self.role)?;
        (package
            .role(self.role)
            .observe_executable_mapping(self.pid)?
            == self.executable)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)
    }
}

fn observe_start(
    pid: NonZeroU32,
) -> Result<MacOsProcessStartIdentity, MacOsPackagedWriterObservationError> {
    MacOsProcessStartIdentity::observe(pid)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)
}

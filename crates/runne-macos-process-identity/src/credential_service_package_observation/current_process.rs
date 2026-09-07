use std::num::NonZeroU32;

use crate::MacOsProcessStartIdentity;
use crate::packaged_writer_observation::security_code::NativeCodeObservation;

use super::MacOsCredentialServicePackageObservationError;
use super::package::ServicePackage;

pub(super) struct CurrentServiceProcess {
    pid: NonZeroU32,
    start: MacOsProcessStartIdentity,
    code: NativeCodeObservation,
    executable: crate::ffi::ExecutableVnodeIdentity,
}

impl CurrentServiceProcess {
    pub(super) fn capture(
        package: &ServicePackage,
        code: NativeCodeObservation,
        pid: NonZeroU32,
        start: MacOsProcessStartIdentity,
    ) -> Result<Self, MacOsCredentialServicePackageObservationError> {
        code.revalidate().map_err(map)?;
        package.require_service_locator(code.main_executable())?;
        let executable = package
            .service_artifact()
            .observe_executable_mapping(pid)
            .map_err(map)?;
        (observe_start(pid)? == start)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        Ok(Self {
            pid,
            start,
            code,
            executable,
        })
    }

    pub(super) fn revalidate(
        &self,
        package: &ServicePackage,
    ) -> Result<NativeCodeObservation, MacOsCredentialServicePackageObservationError> {
        (observe_start(self.pid)? == self.start)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let fresh = NativeCodeObservation::capture_self().map_err(map)?;
        self.code.matches_fresh(&fresh).map_err(map)?;
        package.require_service_locator(fresh.main_executable())?;
        let executable = package
            .service_artifact()
            .observe_executable_mapping(self.pid)
            .map_err(map)?;
        (executable == self.executable && observe_start(self.pid)? == self.start)
            .then_some(fresh)
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)
    }

    pub(super) const fn code(&self) -> &NativeCodeObservation {
        &self.code
    }
}

pub(super) fn observe_current_identity()
-> Result<(NonZeroU32, MacOsProcessStartIdentity), MacOsCredentialServicePackageObservationError> {
    let pid = NonZeroU32::new(std::process::id())
        .ok_or(MacOsCredentialServicePackageObservationError::Unavailable)?;
    Ok((pid, observe_start(pid)?))
}

fn observe_start(
    pid: NonZeroU32,
) -> Result<MacOsProcessStartIdentity, MacOsCredentialServicePackageObservationError> {
    MacOsProcessStartIdentity::observe(pid)
        .map_err(|_| MacOsCredentialServicePackageObservationError::Rejected)
}

const fn map(
    error: crate::MacOsPackagedWriterObservationError,
) -> MacOsCredentialServicePackageObservationError {
    match error {
        crate::MacOsPackagedWriterObservationError::Rejected => {
            MacOsCredentialServicePackageObservationError::Rejected
        }
        crate::MacOsPackagedWriterObservationError::Unavailable => {
            MacOsCredentialServicePackageObservationError::Unavailable
        }
    }
}

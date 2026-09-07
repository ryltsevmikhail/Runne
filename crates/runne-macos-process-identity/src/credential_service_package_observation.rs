//! Authority-free observation of the current credential-service package.

mod current_process;
mod layout;
mod package;

#[cfg(test)]
mod tests;

use crate::packaged_writer_observation::security_code::NativeCodeObservation;
use crate::signed_code_identity::service::{
    match_service_dynamic_identity, match_service_static_identities,
};

use current_process::{CurrentServiceProcess, observe_current_identity};
use layout::application_from_service;
use package::ServicePackage;

/// Closed failure surface for current credential-service package observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsCredentialServicePackageObservationError {
    Rejected,
    Unavailable,
}

/// Retained but unverified package observation with no exported facts or authority.
///
/// ```compile_fail
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1>();
/// ```
///
/// ```compile_fail
/// let _ = runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1::default();
/// ```
pub struct MacOsPendingCredentialServicePackageObservationV1 {
    package: ServicePackage,
    process: CurrentServiceProcess,
}

/// Verified, inert package observation with no exported facts or authority.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_macos_process_identity::MacOsVerifiedCredentialServicePackageV1>();
/// ```
pub struct MacOsVerifiedCredentialServicePackageV1 {
    _package: ServicePackage,
    _process: CurrentServiceProcess,
}

impl MacOsPendingCredentialServicePackageObservationV1 {
    /// Captures the exact package enclosing the current credential-service process.
    ///
    /// # Errors
    ///
    /// Fails closed when dynamic code, package layout, retained artifacts, or
    /// current process identity cannot be observed exactly.
    pub fn capture_current() -> Result<Self, MacOsCredentialServicePackageObservationError> {
        let (pid, start) = observe_current_identity()?;
        let code = NativeCodeObservation::capture_self().map_err(map)?;
        let application = application_from_service(code.main_executable())?;
        let package = ServicePackage::capture(&application)?;
        let process = CurrentServiceProcess::capture(&package, code, pid, start)?;
        package.revalidate()?;
        Ok(Self { package, process })
    }

    /// Matches retained observations against one already-exact V3 signed release.
    ///
    /// # Errors
    ///
    /// Rejects V2-only releases and any retained, static, dynamic, process, or
    /// final revalidation mismatch.
    pub fn verify_exact(
        self,
        release: &runne_api::VerifiedSignedInstalledReleaseV2,
    ) -> Result<
        MacOsVerifiedCredentialServicePackageV1,
        MacOsCredentialServicePackageObservationError,
    > {
        let tuple = release
            .native_enrollment_tuple_v3()
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        self.package.revalidate()?;
        let candidate = self.package.candidate_binding()?;
        release
            .matches_native_enrollment_v3_candidate_binding(&candidate)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let digests = self.package.release_digests(&candidate)?;
        tuple
            .matches_release_digests(&digests)
            .then_some(())
            .ok_or(MacOsCredentialServicePackageObservationError::Rejected)?;
        let paths = self.package.static_paths();
        match_service_static_identities(tuple, &paths).map_err(map)?;
        match_service_dynamic_identity(tuple, self.process.code().code()).map_err(map)?;
        self.package.revalidate()?;
        let fresh = self.process.revalidate(&self.package)?;
        match_service_static_identities(tuple, &paths).map_err(map)?;
        match_service_dynamic_identity(tuple, fresh.code()).map_err(map)?;
        self.package.revalidate()?;
        Ok(MacOsVerifiedCredentialServicePackageV1 {
            _package: self.package,
            _process: self.process,
        })
    }
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

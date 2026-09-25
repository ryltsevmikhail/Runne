use crate::{ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment};
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::{UpdateCoordinator, UpdateCoordinatorError};

impl UpdateCoordinator {
    /// Re-verifies the installed Linux release using paths resolved by Tauri.
    pub fn prepare_linux_installed_native_enrollment(
        &self,
        desktop_executable: &std::path::Path,
        resource_directory: &std::path::Path,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        let Some(verified) = self.verified_installed_native_update(now)? else {
            return Ok(None);
        };
        let paths = crate::updater_metadata::NativeEnrollmentArtifactPathsV1::
            resolve_linux_from_host_paths(desktop_executable, resource_directory)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        let admission = paths
            .admit_verified(&verified)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        Ok(admission.map(|admission| admission.retain_installed_paths(paths)))
    }

    /// Revalidates a prompt-delayed Linux admission against fresh signed paths.
    pub fn refresh_linux_installed_native_enrollment(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
        desktop_executable: &std::path::Path,
        resource_directory: &std::path::Path,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let Some(fresh) =
            self.prepare_linux_installed_native_enrollment(desktop_executable, resource_directory)?
        else {
            return Ok(None);
        };
        Ok(prepared.refresh_from(fresh))
    }

    /// Revalidates confirmed evidence against the current signed tuple and Linux paths.
    pub fn revalidate_linux_confirmed_native_enrollment(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
        desktop_executable: &std::path::Path,
        resource_directory: &std::path::Path,
    ) -> Result<bool, UpdateCoordinatorError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        let Some(verified) = self.verified_installed_native_update(now)? else {
            return Ok(false);
        };
        let paths = crate::updater_metadata::NativeEnrollmentArtifactPathsV1::
            resolve_linux_from_host_paths(desktop_executable, resource_directory)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        Ok(paths
            .admit_verified(&verified)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .is_some_and(|admission| confirmed.matches_admission(&admission)))
    }
}

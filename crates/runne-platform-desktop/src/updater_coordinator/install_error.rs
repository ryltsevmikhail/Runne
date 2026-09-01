use super::{UpdateCoordinatorError, UpdateInstallError};

pub(super) const fn map_install_error(error: UpdateInstallError) -> UpdateCoordinatorError {
    match error {
        UpdateInstallError::ActiveTaskRuns => UpdateCoordinatorError::ActiveTaskRuns,
        UpdateInstallError::InvalidTransition | UpdateInstallError::InvalidDigest => {
            UpdateCoordinatorError::InvalidTransition
        }
    }
}

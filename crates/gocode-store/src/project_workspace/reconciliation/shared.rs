use gocode_application::command_reconciliation::CommandReconciliationRepositoryError as Error;

pub(super) fn map_error(
    error: Error,
) -> gocode_application::ports::ProjectWorkspaceRepositoryError {
    match error {
        Error::Conflict => gocode_application::ports::ProjectWorkspaceRepositoryError::Conflict,
        Error::Unavailable => {
            gocode_application::ports::ProjectWorkspaceRepositoryError::Unavailable
        }
        Error::InvariantViolation => {
            gocode_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation
        }
    }
}

pub(super) fn map_project_error(
    error: gocode_application::ports::ProjectWorkspaceRepositoryError,
) -> Error {
    match error {
        gocode_application::ports::ProjectWorkspaceRepositoryError::Conflict => Error::Conflict,
        gocode_application::ports::ProjectWorkspaceRepositoryError::Unavailable => {
            Error::Unavailable
        }
        _ => Error::InvariantViolation,
    }
}

use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;

pub(super) fn map_error(error: Error) -> runne_application::ports::ProjectWorkspaceRepositoryError {
    match error {
        Error::Conflict => runne_application::ports::ProjectWorkspaceRepositoryError::Conflict,
        Error::Unavailable => {
            runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable
        }
        Error::InvariantViolation => {
            runne_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation
        }
    }
}

pub(super) fn map_project_error(
    error: runne_application::ports::ProjectWorkspaceRepositoryError,
) -> Error {
    match error {
        runne_application::ports::ProjectWorkspaceRepositoryError::Conflict => Error::Conflict,
        runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable => {
            Error::Unavailable
        }
        _ => Error::InvariantViolation,
    }
}

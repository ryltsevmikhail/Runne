use super::StoreTransaction;

/// Closed failures while reserving or validating an enrollment launch generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnrollmentLaunchGenerationError {
    /// The authoritative writer cannot be acquired or is temporarily busy.
    #[error("enrollment launch generation store unavailable")]
    Unavailable,
    /// The canonical launch-generation record is invalid or cannot be trusted.
    #[error("enrollment launch generation store contains corrupt data")]
    CorruptData,
}

impl StoreTransaction {
    /// Reserves the next canonical generation through the authoritative writer.
    ///
    /// The underlying schema operation is atomic. A crashed transition can leave
    /// a gap; callers must treat that as a valid reservation history.
    pub fn reserve_enrollment_launch_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EnrollmentLaunchGenerationError::Unavailable)?;
        crate::schema::reserve_launch_generation_for_prelude(&connection)
            .map_err(map_enrollment_launch_error)
    }

    /// Confirms that a reserved enrollment generation is still canonical.
    ///
    /// Validation is read-only and rejects zero, stale, future, and corrupt
    /// values without repairing or advancing the authoritative counter.
    pub fn validate_enrollment_launch_generation(
        &self,
        generation: u64,
    ) -> Result<(), EnrollmentLaunchGenerationError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EnrollmentLaunchGenerationError::Unavailable)?;
        crate::schema::validate_reserved_launch_generation(&connection, generation)
            .map_err(map_enrollment_launch_error)
    }

    /// Atomically consumes the current enrollment reservation through the writer.
    pub fn consume_enrollment_launch_generation(
        &self,
        generation: u64,
    ) -> Result<(), EnrollmentLaunchGenerationError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EnrollmentLaunchGenerationError::Unavailable)?;
        crate::schema::consume_reserved_launch_generation(&connection, generation)
            .map_err(map_enrollment_launch_error)
    }
}

impl runne_application::local_session::EnrollmentLaunchGenerationStore for StoreTransaction {
    fn consume_reserved_enrollment_generation(
        &self,
        generation: u64,
    ) -> Result<(), runne_application::local_session::EnrollmentLaunchGenerationConsumeError> {
        self.consume_enrollment_launch_generation(generation)
            .map_err(map_enrollment_launch_consume_error)
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, runne_application::local_session::EnrollmentLaunchGenerationConsumeError> {
        self.reserve_enrollment_launch_generation()
            .map_err(map_enrollment_launch_consume_error)
    }
}

fn map_enrollment_launch_consume_error(
    error: EnrollmentLaunchGenerationError,
) -> runne_application::local_session::EnrollmentLaunchGenerationConsumeError {
    use runne_application::local_session::EnrollmentLaunchGenerationConsumeError;
    match error {
        EnrollmentLaunchGenerationError::Unavailable => {
            EnrollmentLaunchGenerationConsumeError::Unavailable
        }
        EnrollmentLaunchGenerationError::CorruptData => {
            EnrollmentLaunchGenerationConsumeError::Rejected
        }
    }
}

fn map_enrollment_launch_error(error: rusqlite::Error) -> EnrollmentLaunchGenerationError {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            EnrollmentLaunchGenerationError::Unavailable
        }
        _ => EnrollmentLaunchGenerationError::CorruptData,
    }
}

/// Closed failures while atomically consuming a protected enrollment generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentLaunchGenerationConsumeError {
    /// The authoritative writer cannot currently consume the reservation.
    Unavailable,
    /// The reservation is missing, stale, replayed, or otherwise untrusted.
    Rejected,
}

/// Authoritative one-time consumer for a daemon-owned enrollment generation.
pub trait EnrollmentLaunchGenerationStore: Send + Sync {
    /// Atomically consumes exactly the supplied currently reserved generation.
    fn consume_reserved_enrollment_generation(
        &self,
        generation: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError>;
}

pub(crate) struct UnavailableEnrollmentLaunchGenerationStore;

impl EnrollmentLaunchGenerationStore for UnavailableEnrollmentLaunchGenerationStore {
    fn consume_reserved_enrollment_generation(
        &self,
        _: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError> {
        Err(EnrollmentLaunchGenerationConsumeError::Unavailable)
    }
}

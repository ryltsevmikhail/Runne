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

    /// Atomically reserves the durable successor of the canonical generation.
    ///
    /// The reservation is the authoritative counter advance itself. Callers
    /// must admit it only when it equals their exact current `launch_generation
    /// + 1`; zero, stale, gapped, or overflowed values fail closed.
    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationConsumeError>;
}

pub(crate) struct UnavailableEnrollmentLaunchGenerationStore;

impl EnrollmentLaunchGenerationStore for UnavailableEnrollmentLaunchGenerationStore {
    fn consume_reserved_enrollment_generation(
        &self,
        _: u64,
    ) -> Result<(), EnrollmentLaunchGenerationConsumeError> {
        Err(EnrollmentLaunchGenerationConsumeError::Unavailable)
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, EnrollmentLaunchGenerationConsumeError> {
        Err(EnrollmentLaunchGenerationConsumeError::Unavailable)
    }
}

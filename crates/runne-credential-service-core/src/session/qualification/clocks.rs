use std::time::Instant;

/// Private paired source. The future host calls it only after acquiring the core guard.
pub(super) trait QualificationClockSource {
    fn wall_unix_millis(&self) -> u64;
    fn monotonic_now(&self) -> Instant;
}

/// A non-constructible pair sampled at one locked qualification transition boundary.
pub(super) struct LockedCredentialServiceClocks {
    wall_unix_millis: u64,
    monotonic_now: Instant,
}

impl LockedCredentialServiceClocks {
    pub(super) fn sample_pair(source: &impl QualificationClockSource) -> Self {
        Self {
            wall_unix_millis: source.wall_unix_millis(),
            monotonic_now: source.monotonic_now(),
        }
    }

    pub(super) const fn wall_unix_millis(&self) -> u64 {
        self.wall_unix_millis
    }

    pub(super) const fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }
}

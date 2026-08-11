use crate::protocol::ProtocolError;

#[allow(clippy::redundant_pub_crate)]
pub(super) const MAX_OFFER_MILLIS: u64 = 30_000;

/// Caller-injected clock sample. Wall time may move backwards; the monotonic
/// source anchors effective time for a launch-local protocol exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSample {
    pub wall_millis: u64,
    pub monotonic_millis: u64,
}

/// Monotonic effective-time derivation for protected-channel expiry checks.
#[derive(Debug, Default)]
pub struct ProtocolClock {
    anchor: Option<ClockSample>,
    previous: Option<u64>,
    previous_monotonic: Option<u64>,
}

impl ProtocolClock {
    /// Computes `max(wall, anchored monotonic, previous)` without accepting a
    /// monotonic rollback or an overflowed anchor arithmetic operation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for monotonic rollback or arithmetic overflow.
    pub fn observe(&mut self, sample: ClockSample) -> Result<u64, ProtocolError> {
        if self
            .previous_monotonic
            .is_some_and(|previous| sample.monotonic_millis < previous)
        {
            return Err(ProtocolError::ClockRegression);
        }
        let anchor = self.anchor.get_or_insert(sample);
        let elapsed = sample
            .monotonic_millis
            .checked_sub(anchor.monotonic_millis)
            .ok_or(ProtocolError::ClockRegression)?;
        let anchored = anchor
            .wall_millis
            .checked_add(elapsed)
            .ok_or(ProtocolError::ClockOverflow)?;
        let effective = self.previous.map_or_else(
            || anchored.max(sample.wall_millis),
            |previous| previous.max(anchored).max(sample.wall_millis),
        );
        self.previous = Some(effective);
        self.previous_monotonic = Some(sample.monotonic_millis);
        Ok(effective)
    }

    /// Establishes an absolute deadline no more than 30 seconds after the
    /// effective time represented by `sample`.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid TTL, clock rollback, or overflow.
    pub fn deadline(&mut self, sample: ClockSample, ttl_millis: u64) -> Result<u64, ProtocolError> {
        if ttl_millis == 0 || ttl_millis > MAX_OFFER_MILLIS {
            return Err(ProtocolError::Rejected);
        }
        self.observe(sample)?
            .checked_add(ttl_millis)
            .ok_or(ProtocolError::ClockOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_regression_is_clamped_but_monotonic_rollback_rejects() {
        let mut clock = ProtocolClock::default();
        assert_eq!(
            clock.observe(ClockSample {
                wall_millis: 100,
                monotonic_millis: 10
            }),
            Ok(100)
        );
        assert_eq!(
            clock.observe(ClockSample {
                wall_millis: 1,
                monotonic_millis: 12
            }),
            Ok(102)
        );
        assert_eq!(
            clock.observe(ClockSample {
                wall_millis: 200,
                monotonic_millis: 11
            }),
            Err(ProtocolError::ClockRegression)
        );
    }

    #[test]
    fn deadline_is_absolute_bounded_and_overflow_safe() {
        let mut clock = ProtocolClock::default();
        assert_eq!(
            clock.deadline(
                ClockSample {
                    wall_millis: 50,
                    monotonic_millis: 50
                },
                30_001
            ),
            Err(ProtocolError::Rejected)
        );
        assert_eq!(
            clock.deadline(
                ClockSample {
                    wall_millis: u64::MAX,
                    monotonic_millis: 1
                },
                1
            ),
            Err(ProtocolError::ClockOverflow)
        );
    }
}

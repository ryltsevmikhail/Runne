#![allow(unsafe_code)]

#[cfg(target_arch = "aarch64")]
use std::mem::MaybeUninit;

/// macOS boot-domain monotonic clock for authenticated cross-process tickets.
pub struct MacOsContinuousClock;

/// Failure to read or convert the macOS continuous clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacOsContinuousClockError {
    /// The clock is deliberately unavailable outside the Apple Silicon tuple.
    Unavailable,
    /// The kernel did not return a usable mach timebase.
    TimebaseUnavailable,
    /// The kernel returned a zero or otherwise invalid conversion ratio.
    InvalidTimebase,
    /// Exact conversion to milliseconds exceeded the protocol representation.
    Overflow,
}

impl MacOsContinuousClock {
    /// Returns milliseconds in the macOS continuous boot-time domain.
    ///
    /// # Errors
    ///
    /// Returns [`MacOsContinuousClockError::Unavailable`] on non-Apple-Silicon
    /// macOS targets, and fails closed if kernel conversion data is unusable.
    pub fn now_millis() -> Result<u64, MacOsContinuousClockError> {
        #[cfg(target_arch = "aarch64")]
        {
            let timebase = timebase()?;
            // SAFETY: Darwin exposes this process-local, argument-free clock.
            let ticks = unsafe { mach_continuous_time() };
            ticks_to_millis(ticks, timebase.numerator, timebase.denominator)
        }
        #[cfg(not(target_arch = "aarch64"))]
        Err(MacOsContinuousClockError::Unavailable)
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct MachTimebaseInfo {
    numerator: u32,
    denominator: u32,
}

#[cfg(target_arch = "aarch64")]
#[link(name = "System")]
unsafe extern "C" {
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[cfg(target_arch = "aarch64")]
fn timebase() -> Result<MachTimebaseInfo, MacOsContinuousClockError> {
    let mut value = MaybeUninit::<MachTimebaseInfo>::zeroed();
    // SAFETY: `value` is a valid writable mach timebase buffer.
    let result = unsafe { mach_timebase_info(value.as_mut_ptr()) };
    if result != 0 {
        return Err(MacOsContinuousClockError::TimebaseUnavailable);
    }
    // SAFETY: a successful mach_timebase_info call initializes the result.
    let value = unsafe { value.assume_init() };
    (value.numerator != 0 && value.denominator != 0)
        .then_some(value)
        .ok_or(MacOsContinuousClockError::InvalidTimebase)
}

#[cfg(any(test, target_arch = "aarch64"))]
fn ticks_to_millis(
    ticks: u64,
    numerator: u32,
    denominator: u32,
) -> Result<u64, MacOsContinuousClockError> {
    if numerator == 0 || denominator == 0 {
        return Err(MacOsContinuousClockError::InvalidTimebase);
    }
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(numerator))
        .ok_or(MacOsContinuousClockError::Overflow)?
        / u128::from(denominator);
    u64::try_from(nanos / 1_000_000).map_err(|_| MacOsContinuousClockError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::{MacOsContinuousClockError, ticks_to_millis};

    #[test]
    fn timebase_conversion_keeps_fractional_ticks_until_the_millisecond_boundary() {
        assert_eq!(ticks_to_millis(1_000_000, 125, 3), Ok(41));
    }

    #[test]
    fn timebase_conversion_rejects_invalid_or_unrepresentable_values() {
        assert_eq!(
            ticks_to_millis(1, 0, 1),
            Err(MacOsContinuousClockError::InvalidTimebase)
        );
        assert_eq!(
            ticks_to_millis(u64::MAX, u32::MAX, 1),
            Err(MacOsContinuousClockError::Overflow)
        );
    }
}

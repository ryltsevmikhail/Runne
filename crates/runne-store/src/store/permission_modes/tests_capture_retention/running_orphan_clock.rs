//! Shorter shared scenario budget; independent C collector keeps its10s cap.
//! Created only by S; W/R inherit the exact value, never a fresh role deadline.
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

const TICK: u64 = 10_000_000;
const SCENARIO: u64 = 8_000_000_000;

fn component(text: &str) -> Result<u64, &'static str> {
    let (seconds, fraction) = text.split_once('.').ok_or("uptime decimal")?;
    if seconds.is_empty()
        || seconds.len() > 20
        || fraction.len() != 2
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("uptime digits");
    }
    seconds
        .parse::<u64>()
        .map_err(|_| "uptime seconds overflow")?
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction.parse::<u64>().ok()? * TICK))
        .ok_or("uptime nanoseconds overflow")
}

fn parse(text: &str) -> Result<u64, &'static str> {
    if text.len() > 128 || !text.is_ascii() {
        return Err("bounded ASCII uptime");
    }
    let text = text.strip_suffix('\n').ok_or("uptime final LF")?;
    let (elapsed, idle) = text.split_once(' ').ok_or("uptime fields")?;
    let value = component(elapsed)?;
    component(idle)?;
    Ok(value)
}

fn now() -> Result<u64, &'static str> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/uptime")
        .map_err(|_| "required guest boot clock")?;
    if !file.metadata().map_err(|_| "clock metadata")?.is_file() {
        return Err("regular clock diagnostic");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| "clock read")?;
    if bytes.len() > 128 {
        return Err("bounded uptime read");
    }
    parse(std::str::from_utf8(&bytes).map_err(|_| "clock UTF8")?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Deadline(pub u64);

impl Deadline {
    fn from_start(start: u64) -> Self {
        // /proc/uptime floors to centiseconds; reserve one tick at creation.
        Self(start.checked_add(SCENARIO - TICK).unwrap())
    }

    pub(super) fn new_supervisor() -> Self {
        // No exported C deadline exists. This internal8s budget is DISTINCT
        // from C's10s budget, which began earlier and can refuse first.
        // No guaranteed2s adoption reserve or workload readiness is claimed.
        Self::from_start(now().expect("required guest boot clock"))
    }

    fn validate_at(self, current: u64) -> Result<Self, &'static str> {
        match self.0.checked_sub(current) {
            Some(left) if left > 0 && left <= SCENARIO => Ok(self),
            _ => Err("shared scenario deadline expired or out of range"),
        }
    }

    pub(super) fn inherited(value: u64) -> Self {
        Self(value)
            .validate_at(now().expect("required guest boot clock"))
            .unwrap()
    }

    pub(super) fn check(self) {
        self.validate_at(now().expect("required guest boot clock"))
            .unwrap();
    }

    pub(super) fn remaining(self) -> Duration {
        self.try_remaining()
            .expect("positive conservative remaining budget")
    }

    fn remaining_at(self, current: u64) -> Result<Duration, &'static str> {
        self.validate_at(current)?;
        let left = self
            .0
            .checked_sub(current)
            .and_then(|value| value.checked_sub(TICK))
            .ok_or("positive conservative remaining budget")?;
        if left == 0 {
            return Err("positive conservative remaining budget");
        }
        Ok(Duration::from_nanos(left))
    }

    pub(super) fn try_remaining(self) -> Result<Duration, &'static str> {
        // Owned-child transport propagates expiry/IO errors with the live handle.
        self.remaining_at(now()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_clock_decimal_is_bounded_and_checked() {
        assert_eq!(parse("0.00 0.00\n"), Ok(0));
        assert_eq!(parse("1.25 2.50\n"), Ok(1_250_000_000));
        for value in [
            "",
            "1.25 2.50",
            "1.2 2.50\n",
            "1.25 2.5\n",
            "-1.25 2.50\n",
            "+1.25 2.50\n",
            "1.25 2.50\nextra",
            "1.25  2.50\n",
            "1.25 2.50\r\n",
            "1.25 2.50\n\n",
            "18446744073709551616.00 0.00\n",
            "18446744073709551615.00 0.00\n",
            "1.25 2.50\0\n",
            "1.25 2.é0\n",
        ] {
            assert!(parse(value).is_err(), "{value:?}");
        }
        assert!(parse(&"0".repeat(129)).is_err());
    }

    #[test]
    fn inherited_deadline_preserves_value_and_expires_without_role_reset() {
        let value = Deadline::from_start(1_000_000_000);
        assert_eq!(value.0, 8_990_000_000);
        assert_eq!(value.validate_at(1_000_000_000), Ok(value));
        assert_eq!(value.validate_at(8_980_000_000), Ok(value));
        assert!(value.validate_at(value.0).is_err());
        assert!(value.validate_at(value.0 + 1).is_err());
        assert!(Deadline(0).validate_at(0).is_err());
        assert!(Deadline(SCENARIO + 1).validate_at(0).is_err());
    }

    #[test]
    fn fallible_remaining_never_grants_the_reserved_tick_or_resets_deadline() {
        let deadline = Deadline(100_000_000);
        assert_eq!(
            deadline.remaining_at(80_000_000),
            Ok(Duration::from_millis(10))
        );
        assert!(deadline.remaining_at(90_000_000).is_err());
        assert!(deadline.remaining_at(99_000_000).is_err());
        assert!(deadline.remaining_at(100_000_000).is_err());
        assert!(deadline.remaining_at(100_000_001).is_err());
        assert!(Deadline(SCENARIO + 1).remaining_at(0).is_err());
    }
}

//! Domain timestamp — microseconds since Unix epoch.
//!
//! Domain code never reads the wall clock. `Timestamp` values are provided
//! by the application layer or persistence adapter.

use core::fmt;

/// Microseconds since Unix epoch (1970-01-01T00:00:00Z).
///
/// Domain does not produce timestamps — it receives them from the
/// application or persistence layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Construct a `Timestamp` from a microsecond count.
    pub const fn from_unix_micros(micros: i64) -> Self {
        Self(micros)
    }

    /// Return the microsecond count.
    pub const fn as_unix_micros(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Output as ISO-8601-like seconds.micros since epoch.
        // Use unsigned arithmetic to avoid sign issues with negative values.
        let negative = self.0 < 0;
        let abs_val: u64 = if negative {
            self.0.unsigned_abs()
        } else {
            self.0 as u64
        };
        let secs = abs_val / 1_000_000;
        let micros = abs_val % 1_000_000;
        if negative {
            write!(f, "-")?;
        }
        write!(f, "{}.{:06}", secs, micros)
    }
}

impl From<i64> for Timestamp {
    fn from(micros: i64) -> Self {
        Self(micros)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_from_unix_micros() {
        let ts = Timestamp::from_unix_micros(1_700_000_000_000_000);
        assert_eq!(ts.as_unix_micros(), 1_700_000_000_000_000);
    }

    #[test]
    fn test_timestamp_from_i64() {
        let ts: Timestamp = 42.into();
        assert_eq!(ts, Timestamp::from_unix_micros(42));
    }

    #[test]
    fn test_timestamp_display() {
        let ts = Timestamp::from_unix_micros(1_700_000_012_345_678);
        let s = ts.to_string();
        assert_eq!(s, "1700000012.345678");
    }

    #[test]
    fn test_timestamp_display_negative() {
        let ts = Timestamp::from_unix_micros(-1);
        let s = ts.to_string();
        assert_eq!(s, "-0.000001");
    }

    #[test]
    fn test_timestamp_ord() {
        let a = Timestamp::from_unix_micros(100);
        let b = Timestamp::from_unix_micros(200);
        assert!(a < b);
    }

    #[test]
    fn test_timestamp_debug() {
        let ts = Timestamp::from_unix_micros(100);
        assert!(format!("{:?}", ts).contains("Timestamp"));
    }
}

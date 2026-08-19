//! Runtime configuration with validation.

use core::fmt;
use std::time::Duration;

/// Error returned when a [`RuntimeConfig`] fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStartError {
    /// A capacity field is zero.
    ZeroCapacity {
        /// The field name that was zero.
        field: &'static str,
    },
    /// A timeout field is zero.
    ZeroTimeout {
        /// The field name that was zero.
        field: &'static str,
    },
}

impl fmt::Display for RuntimeStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity { field } => {
                write!(f, "capacity field '{}' must be > 0", field)
            }
            Self::ZeroTimeout { field } => {
                write!(f, "timeout field '{}' must be > 0", field)
            }
        }
    }
}

impl std::error::Error for RuntimeStartError {}

/// Configuration for the Runne runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Capacity of the global ingress channel (bounded mpsc).
    pub ingress_capacity: usize,
    /// Capacity of each per-taskrun mailbox channel.
    pub per_run_mailbox_capacity: usize,
    /// Maximum number of concurrently active workers (per taskrun).
    pub max_active_workers: usize,
    /// Maximum number of in-flight requests across all workers.
    pub max_in_flight_requests: usize,
    /// Maximum number of concurrent blocking operations per worker.
    pub worker_max_concurrent_blocking: usize,
    /// Timeout for acquiring a blocking pool permit.
    pub blocking_acquire_timeout: Duration,
    /// Timeout after which an idle worker exits.
    pub worker_idle_timeout: Duration,
}

impl RuntimeConfig {
    /// Validate that all capacity and timeout fields are non-zero.
    pub fn validate(&self) -> Result<(), RuntimeStartError> {
        if self.ingress_capacity == 0 {
            return Err(RuntimeStartError::ZeroCapacity {
                field: "ingress_capacity",
            });
        }
        if self.per_run_mailbox_capacity == 0 {
            return Err(RuntimeStartError::ZeroCapacity {
                field: "per_run_mailbox_capacity",
            });
        }
        if self.max_active_workers == 0 {
            return Err(RuntimeStartError::ZeroCapacity {
                field: "max_active_workers",
            });
        }
        if self.max_in_flight_requests == 0 {
            return Err(RuntimeStartError::ZeroCapacity {
                field: "max_in_flight_requests",
            });
        }
        if self.worker_max_concurrent_blocking == 0 {
            return Err(RuntimeStartError::ZeroCapacity {
                field: "worker_max_concurrent_blocking",
            });
        }
        if self.blocking_acquire_timeout.is_zero() {
            return Err(RuntimeStartError::ZeroTimeout {
                field: "blocking_acquire_timeout",
            });
        }
        if self.worker_idle_timeout.is_zero() {
            return Err(RuntimeStartError::ZeroTimeout {
                field: "worker_idle_timeout",
            });
        }
        Ok(())
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            ingress_capacity: 1024,
            per_run_mailbox_capacity: 64,
            max_active_workers: 32,
            max_in_flight_requests: 64,
            worker_max_concurrent_blocking: 4,
            blocking_acquire_timeout: Duration::from_secs(30),
            worker_idle_timeout: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        RuntimeConfig::default().validate().unwrap();
    }

    #[test]
    fn test_zero_ingress_capacity() {
        let err = RuntimeConfig {
            ingress_capacity: 0,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroCapacity {
                field: "ingress_capacity"
            }
        ));
    }

    #[test]
    fn test_zero_per_run_mailbox_capacity() {
        let err = RuntimeConfig {
            per_run_mailbox_capacity: 0,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroCapacity {
                field: "per_run_mailbox_capacity"
            }
        ));
    }

    #[test]
    fn test_zero_max_active_workers() {
        let err = RuntimeConfig {
            max_active_workers: 0,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroCapacity {
                field: "max_active_workers"
            }
        ));
    }

    #[test]
    fn test_zero_max_in_flight_requests() {
        let err = RuntimeConfig {
            max_in_flight_requests: 0,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroCapacity {
                field: "max_in_flight_requests"
            }
        ));
    }

    #[test]
    fn test_zero_worker_max_concurrent_blocking() {
        let err = RuntimeConfig {
            worker_max_concurrent_blocking: 0,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroCapacity {
                field: "worker_max_concurrent_blocking"
            }
        ));
    }

    #[test]
    fn test_zero_blocking_acquire_timeout() {
        let err = RuntimeConfig {
            blocking_acquire_timeout: Duration::ZERO,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroTimeout {
                field: "blocking_acquire_timeout"
            }
        ));
    }

    #[test]
    fn test_zero_worker_idle_timeout() {
        let err = RuntimeConfig {
            worker_idle_timeout: Duration::ZERO,
            ..RuntimeConfig::default()
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            RuntimeStartError::ZeroTimeout {
                field: "worker_idle_timeout"
            }
        ));
    }
}

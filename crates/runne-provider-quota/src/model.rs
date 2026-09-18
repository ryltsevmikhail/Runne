use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::request::QuotaIdentity;

/// Subscription quota window kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaWindowKind {
    /// Provider window whose duration or unit is unspecified.
    TokenQuotaUnspecified,
    /// Explicit five-hour rolling window.
    FiveHourTime,
    /// Explicit weekly rolling window.
    WeeklyTime,
    /// Monthly MCP/time window.
    MonthlyTime,
}

/// Sanitized window evidence. Missing values remain missing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaWindow {
    kind: QuotaWindowKind,
    used: Option<u64>,
    limit: Option<u64>,
    remaining: Option<u64>,
    percent_used: Option<u8>,
    reset_at_unix_seconds: Option<u64>,
}

impl QuotaWindow {
    /// Constructs a checked quota window without deriving missing provider values.
    pub fn new(
        kind: QuotaWindowKind,
        used: Option<u64>,
        limit: Option<u64>,
        remaining: Option<u64>,
        percent_used: Option<u8>,
        reset_at_unix_seconds: Option<u64>,
    ) -> Result<Self, QuotaModelError> {
        if percent_used.is_some_and(|value| value > 100)
            || reset_at_unix_seconds.is_some_and(|value| value == 0)
            || remaining.zip(limit).is_some_and(|(r, l)| r > l)
            || used.zip(limit).is_some_and(|(u, l)| u > l)
        {
            return Err(QuotaModelError::InvalidWindow);
        }
        if let (Some(used), Some(remaining), Some(limit)) = (used, remaining, limit)
            && used.checked_add(remaining) != Some(limit)
        {
            return Err(QuotaModelError::InvalidWindow);
        }
        Ok(Self {
            kind,
            used,
            limit,
            remaining,
            percent_used,
            reset_at_unix_seconds,
        })
    }
    /// Returns the window kind.
    pub const fn kind(&self) -> QuotaWindowKind {
        self.kind
    }
    /// Returns explicitly observed usage.
    pub const fn used(&self) -> Option<u64> {
        self.used
    }
    /// Returns explicitly observed limit.
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }
    /// Returns explicitly observed remaining quota.
    pub const fn remaining(&self) -> Option<u64> {
        self.remaining
    }
    /// Returns provider-reported usage percentage.
    pub const fn percent_used(&self) -> Option<u8> {
        self.percent_used
    }
    /// Returns an explicitly supplied reset timestamp.
    pub const fn reset_at_unix_seconds(&self) -> Option<u64> {
        self.reset_at_unix_seconds
    }
    /// Returns whether this window is explicitly exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.remaining == Some(0) || self.percent_used == Some(100)
    }
}

/// Source of a quota observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaObservationSource {
    /// Provider API response.
    ProviderApi,
    /// Explicit local owner snapshot.
    LocalConfig,
    /// No trusted provider observation.
    Unknown,
}

/// Availability state presented to runtime/UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaAvailability {
    /// At least one trusted window exists.
    Known,
    /// Schema/source does not establish a remaining amount.
    Unknown,
    /// Provider explicitly reported exhaustion.
    Exhausted,
}

/// Model/state validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum QuotaModelError {
    /// Provider or credential identity is invalid.
    #[error("quota identity invalid")]
    InvalidIdentity,
    /// Counters or percentage contradict the provider evidence.
    #[error("quota window invalid")]
    InvalidWindow,
    /// Snapshot has no trusted window evidence.
    #[error("quota snapshot has no trusted windows")]
    EmptySnapshot,
    /// Snapshot identity differs from state identity without a rotation.
    #[error("quota identity changed")]
    IdentityChanged,
    /// Observation timestamp moved backwards.
    #[error("quota observation timestamp regressed")]
    ObservationRegressed,
    /// Local usage counters overflowed.
    #[error("local quota usage overflow")]
    UsageOverflow,
}

/// Immutable provider quota observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaSnapshot {
    identity: QuotaIdentity,
    source: QuotaObservationSource,
    observed_at_unix_seconds: u64,
    windows: Vec<QuotaWindow>,
    availability: QuotaAvailability,
}

impl QuotaSnapshot {
    /// Constructs a trusted snapshot and derives availability only from explicit evidence.
    pub fn new(
        identity: QuotaIdentity,
        source: QuotaObservationSource,
        observed_at_unix_seconds: u64,
        windows: Vec<QuotaWindow>,
    ) -> Result<Self, QuotaModelError> {
        if observed_at_unix_seconds == 0
            || windows.is_empty()
            || source == QuotaObservationSource::Unknown
        {
            return Err(QuotaModelError::EmptySnapshot);
        }
        let availability = if windows.iter().any(QuotaWindow::is_exhausted) {
            QuotaAvailability::Exhausted
        } else if windows.iter().any(|window| window.remaining().is_some()) {
            QuotaAvailability::Known
        } else {
            QuotaAvailability::Unknown
        };
        Ok(Self {
            identity,
            source,
            observed_at_unix_seconds,
            windows,
            availability,
        })
    }
    /// Returns the identity binding.
    pub const fn identity(&self) -> &QuotaIdentity {
        &self.identity
    }
    /// Returns observation source.
    pub const fn source(&self) -> QuotaObservationSource {
        self.source
    }
    /// Returns observation time.
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    /// Returns sanitized windows.
    pub fn windows(&self) -> &[QuotaWindow] {
        &self.windows
    }
    /// Returns derived availability.
    pub const fn availability(&self) -> QuotaAvailability {
        self.availability
    }
}

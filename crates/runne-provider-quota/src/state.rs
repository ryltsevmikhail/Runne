use crate::{QuotaAvailability, QuotaIdentity, QuotaModelError, QuotaSnapshot};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_FRESHNESS_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Decision at the dispatch admission boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaDecision {
    /// A fresh snapshot has an explicit nonzero remaining value.
    Allow,
    /// No trusted remaining value exists; caller may use its separate token budget.
    AllowUnknown,
    /// Observation is outside its freshness window; caller may use token budget.
    AllowStale,
    /// A trusted provider observation says the window is exhausted.
    PauseExhausted {
        /// Provider supplied reset time when available.
        reset_at_unix_seconds: Option<u64>,
    },
    /// State storage was unavailable; dispatch must fail closed before secrets/network.
    Unavailable,
}

/// Sanitized reason for the last refresh failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuotaRefreshStatus {
    /// Provider schema was missing or changed.
    UnknownSchema,
    /// Provider requires a console refresh.
    ConsoleRequired,
    /// Request was rate limited; retry is caller-owned.
    RateLimited {
        /// Bounded retry delay from the response header.
        retry_after_seconds: Option<u64>,
    },
    /// Transport was unavailable.
    TransportUnavailable,
    /// Provider rejected the credential.
    Unauthorized,
}

/// Local usage counters kept separately from provider remaining quota.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct LocalUsageCounters {
    input_tokens: u64,
    output_tokens: u64,
    last_observed_at_unix_seconds: Option<u64>,
}

impl LocalUsageCounters {
    /// Returns locally observed input tokens.
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }
    /// Returns locally observed output tokens.
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }
    /// Returns the last local usage observation time.
    pub const fn last_observed_at_unix_seconds(&self) -> Option<u64> {
        self.last_observed_at_unix_seconds
    }
}

/// Serializable quota state suitable for later durable runtime persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaState {
    identity: QuotaIdentity,
    max_age_seconds: u64,
    snapshot: Option<QuotaSnapshot>,
    local_usage: LocalUsageCounters,
    last_refresh: Option<QuotaRefreshStatus>,
}

#[derive(Deserialize)]
struct RawQuotaState {
    identity: QuotaIdentity,
    max_age_seconds: u64,
    snapshot: Option<QuotaSnapshot>,
    local_usage: LocalUsageCounters,
    last_refresh: Option<QuotaRefreshStatus>,
}

impl<'de> Deserialize<'de> for QuotaState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawQuotaState::deserialize(deserializer)?;
        if raw.max_age_seconds == 0
            || raw.local_usage.last_observed_at_unix_seconds == Some(0)
            || raw
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.identity() != &raw.identity)
        {
            return Err(serde::de::Error::custom("invalid quota state"));
        }
        Ok(Self {
            identity: raw.identity,
            max_age_seconds: raw.max_age_seconds.clamp(1, MAX_FRESHNESS_SECONDS),
            snapshot: raw.snapshot,
            local_usage: raw.local_usage,
            last_refresh: raw.last_refresh,
        })
    }
}

impl QuotaState {
    /// Creates an empty fail-closed state for one provider/credential version.
    pub fn new(identity: QuotaIdentity, max_age_seconds: u64) -> Self {
        Self {
            identity,
            max_age_seconds: max_age_seconds.clamp(1, MAX_FRESHNESS_SECONDS),
            snapshot: None,
            local_usage: LocalUsageCounters::default(),
            last_refresh: None,
        }
    }
    /// Accepts a newer valid snapshot or rejects time/identity regressions.
    pub fn apply_snapshot(&mut self, snapshot: QuotaSnapshot) -> Result<(), QuotaModelError> {
        if snapshot.identity().provider_id() != self.identity.provider_id() {
            return Err(QuotaModelError::IdentityChanged);
        }
        if snapshot.identity().credential_version() < self.identity.credential_version() {
            return Err(QuotaModelError::IdentityChanged);
        }
        if snapshot.identity().credential_version() > self.identity.credential_version() {
            self.identity = snapshot.identity().clone();
            self.snapshot = None;
            self.local_usage = LocalUsageCounters::default();
        } else if self.snapshot.as_ref().is_some_and(|previous| {
            snapshot.observed_at_unix_seconds() <= previous.observed_at_unix_seconds()
        }) {
            return Err(QuotaModelError::ObservationRegressed);
        } else if self
            .snapshot
            .as_ref()
            .is_some_and(|previous| previous.availability() == QuotaAvailability::Exhausted)
            && snapshot.availability() == QuotaAvailability::Unknown
        {
            self.last_refresh = Some(QuotaRefreshStatus::UnknownSchema);
            return Ok(());
        }
        self.snapshot = Some(snapshot);
        self.last_refresh = None;
        Ok(())
    }
    /// Records a refresh failure while retaining any prior trusted snapshot.
    pub fn record_refresh_failure(&mut self, status: QuotaRefreshStatus) {
        self.last_refresh = Some(status);
    }
    /// Records local usage for the current credential version.
    pub fn record_usage(
        &mut self,
        identity: &QuotaIdentity,
        input_tokens: u64,
        output_tokens: u64,
        observed_at_unix_seconds: u64,
    ) -> Result<(), QuotaModelError> {
        if identity != &self.identity {
            return Err(QuotaModelError::IdentityChanged);
        }
        if observed_at_unix_seconds == 0
            || self
                .local_usage
                .last_observed_at_unix_seconds
                .is_some_and(|last| observed_at_unix_seconds < last)
        {
            return Err(QuotaModelError::ObservationRegressed);
        }
        let input_total = self
            .local_usage
            .input_tokens
            .checked_add(input_tokens)
            .ok_or(QuotaModelError::UsageOverflow)?;
        let output_total = self
            .local_usage
            .output_tokens
            .checked_add(output_tokens)
            .ok_or(QuotaModelError::UsageOverflow)?;
        self.local_usage.input_tokens = input_total;
        self.local_usage.output_tokens = output_total;
        self.local_usage.last_observed_at_unix_seconds = Some(observed_at_unix_seconds);
        Ok(())
    }
    /// Computes a fail-closed admission decision at `now`.
    pub fn decision(&self, now_unix_seconds: u64) -> QuotaDecision {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return QuotaDecision::AllowUnknown;
        };
        if snapshot.availability() == QuotaAvailability::Exhausted {
            let mut blocking_reset: Option<u64> = None;
            let mut unknown_reset = false;
            for window in snapshot
                .windows()
                .iter()
                .filter(|window| window.is_exhausted())
            {
                match window.reset_at_unix_seconds() {
                    Some(reset) if now_unix_seconds < reset => {
                        blocking_reset =
                            Some(blocking_reset.map_or(reset, |current| current.max(reset)));
                    }
                    Some(_) => {}
                    None => unknown_reset = true,
                }
            }
            if !unknown_reset && blocking_reset.is_none() {
                return QuotaDecision::AllowUnknown;
            }
            return QuotaDecision::PauseExhausted {
                reset_at_unix_seconds: (!unknown_reset).then_some(blocking_reset).flatten(),
            };
        }
        if now_unix_seconds < snapshot.observed_at_unix_seconds()
            || now_unix_seconds.saturating_sub(snapshot.observed_at_unix_seconds())
                > self.max_age_seconds
        {
            return QuotaDecision::AllowStale;
        }
        match snapshot.availability() {
            QuotaAvailability::Known => QuotaDecision::Allow,
            QuotaAvailability::Unknown | QuotaAvailability::Exhausted => {
                QuotaDecision::AllowUnknown
            }
        }
    }
    /// Returns the current identity.
    pub const fn identity(&self) -> &QuotaIdentity {
        &self.identity
    }
    /// Returns the last accepted provider snapshot.
    pub const fn snapshot(&self) -> Option<&QuotaSnapshot> {
        self.snapshot.as_ref()
    }
    /// Returns local usage counters.
    pub const fn local_usage(&self) -> &LocalUsageCounters {
        &self.local_usage
    }
    /// Returns the sanitized last refresh status.
    pub const fn last_refresh(&self) -> Option<QuotaRefreshStatus> {
        self.last_refresh
    }
}

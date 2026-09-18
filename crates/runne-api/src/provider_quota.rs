use serde::{Deserialize, Serialize};

const MAX_PROVIDER_ID_BYTES: usize = 128;

/// Provenance of a quota projection. Unknown never means unlimited.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaSourceV1 {
    /// Counters were explicitly returned by the provider.
    ProviderReported,
    /// Counters came from an explicit local owner configuration.
    LocalConfig,
    /// Counters were accumulated from completed local requests.
    LocalUsage,
    /// No trusted counter is available.
    Unknown,
}

/// Unit for counters in a quota projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaUnitV1 {
    /// Provider-owned credits.
    Credits,
    /// Request count.
    Requests,
    /// Input/output tokens.
    Tokens,
}

/// Availability of the strongest retained provider evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaAvailabilityV1 {
    /// A provider window has a trusted remaining value.
    Known,
    /// A provider explicitly exhausted at least one window.
    Exhausted,
    /// Evidence exists but is older than the freshness policy.
    Stale,
    /// No trusted remaining value is available.
    Unknown,
}

/// One sanitized provider quota window; missing values remain missing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderQuotaWindowV1 {
    /// Stable window kind label from the provider adapter.
    pub kind: String,
    /// Explicitly observed usage.
    pub used: Option<u64>,
    /// Explicit provider limit.
    pub limit: Option<u64>,
    /// Explicit provider remaining value.
    pub remaining: Option<u64>,
    /// Provider-reported usage percentage when absolute counters are absent.
    pub percent_used: Option<u8>,
    /// Explicit provider reset time in Unix seconds.
    pub reset_at: Option<u64>,
}

/// Renderer-safe quota projection returned by the authenticated runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderQuotaProjectionV1 {
    /// Stable provider identifier.
    pub provider_id: String,
    /// Evidence provenance.
    pub source: ProviderQuotaSourceV1,
    /// Counter unit, absent when source is unknown.
    pub unit: Option<ProviderQuotaUnitV1>,
    /// Explicitly observed or local-used amount.
    pub used: Option<u64>,
    /// Provider-reported window limit, if present.
    pub limit: Option<u64>,
    /// Provider-reported remaining amount, if present.
    pub remaining: Option<u64>,
    /// Provider-attested reset time in Unix seconds, if present.
    pub reset_at: Option<u64>,
    /// Observation time in Unix seconds; zero means no observation.
    pub observed_at: u64,
    /// Strongest availability classification retained by the runtime.
    pub availability: ProviderQuotaAvailabilityV1,
    /// All sanitized provider windows, including windows with unknown units.
    pub windows: Vec<ProviderQuotaWindowV1>,
}

impl ProviderQuotaProjectionV1 {
    /// Creates an explicit unknown projection without fabricating counters.
    #[must_use]
    pub fn unknown(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            source: ProviderQuotaSourceV1::Unknown,
            unit: None,
            used: None,
            limit: None,
            remaining: None,
            reset_at: None,
            observed_at: 0,
            availability: ProviderQuotaAvailabilityV1::Unknown,
            windows: Vec::new(),
        }
    }

    /// Validates the closed renderer projection.
    pub fn validate(&self) -> Result<(), ProviderQuotaProjectionError> {
        if self.provider_id.is_empty()
            || self.provider_id.len() > MAX_PROVIDER_ID_BYTES
            || !self.provider_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ProviderQuotaProjectionError::InvalidProviderId);
        }
        if self.reset_at.is_some_and(|value| value == 0)
            || self
                .limit
                .zip(self.used)
                .is_some_and(|(limit, used)| used > limit)
            || self
                .limit
                .zip(self.remaining)
                .is_some_and(|(limit, remaining)| remaining > limit)
        {
            return Err(ProviderQuotaProjectionError::InvalidCounters);
        }
        for window in &self.windows {
            if window.kind.is_empty()
                || window.kind.len() > 64
                || !window.kind.bytes().all(|byte| byte.is_ascii_graphic())
                || window.reset_at.is_some_and(|value| value == 0)
                || window.percent_used.is_some_and(|value| value > 100)
                || window
                    .limit
                    .zip(window.used)
                    .is_some_and(|(limit, used)| used > limit)
                || window
                    .limit
                    .zip(window.remaining)
                    .is_some_and(|(limit, remaining)| remaining > limit)
            {
                return Err(ProviderQuotaProjectionError::InvalidCounters);
            }
        }
        match self.source {
            ProviderQuotaSourceV1::Unknown
                if self.unit.is_some()
                    || self.used.is_some()
                    || self.limit.is_some()
                    || self.remaining.is_some()
                    || self.reset_at.is_some()
                    || self.observed_at != 0
                    || self.availability != ProviderQuotaAvailabilityV1::Unknown
                    || !self.windows.is_empty() =>
            {
                Err(ProviderQuotaProjectionError::UnknownHasEvidence)
            }
            ProviderQuotaSourceV1::LocalUsage
                if self.unit.is_none()
                    || self.used.is_none()
                    || self.limit.is_some()
                    || self.remaining.is_some()
                    || self.reset_at.is_some()
                    || !self.windows.is_empty()
                    || self.observed_at == 0 =>
            {
                Err(ProviderQuotaProjectionError::InvalidLocalUsage)
            }
            ProviderQuotaSourceV1::ProviderReported | ProviderQuotaSourceV1::LocalConfig
                if (self.unit.is_none() && self.windows.is_empty())
                    || self.observed_at == 0
                    || (self.used.is_none()
                        && self.limit.is_none()
                        && self.remaining.is_none()
                        && self.windows.is_empty()) =>
            {
                Err(ProviderQuotaProjectionError::InvalidProviderEvidence)
            }
            _ => Ok(()),
        }
    }
}

/// Rejected renderer quota projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderQuotaProjectionError {
    /// Provider identity is empty, oversized, or contains controls.
    InvalidProviderId,
    /// Counters contradict an explicit limit.
    InvalidCounters,
    /// Unknown source contains fabricated evidence.
    UnknownHasEvidence,
    /// Local usage has a provider-only limit or no usage unit.
    InvalidLocalUsage,
    /// Provider source contains no counter evidence or unit.
    InvalidProviderEvidence,
}

impl std::fmt::Display for ProviderQuotaProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProviderId => "invalid quota provider id",
            Self::InvalidCounters => "invalid quota counters",
            Self::UnknownHasEvidence => "unknown quota contains evidence",
            Self::InvalidLocalUsage => "invalid local quota usage",
            Self::InvalidProviderEvidence => "invalid provider quota evidence",
        })
    }
}

impl std::error::Error for ProviderQuotaProjectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_projection_contains_no_quota_claims() {
        let projection = ProviderQuotaProjectionV1::unknown("zai");
        assert_eq!(projection.source, ProviderQuotaSourceV1::Unknown);
        assert!(projection.validate().is_ok());
        assert_eq!(
            serde_json::to_value(projection).unwrap()["remaining"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn source_rules_reject_fabricated_or_incoherent_values() {
        let mut projection = ProviderQuotaProjectionV1::unknown("qwen-token-plan");
        projection.remaining = Some(0);
        assert_eq!(
            projection.validate(),
            Err(ProviderQuotaProjectionError::UnknownHasEvidence)
        );
        let local = ProviderQuotaProjectionV1 {
            provider_id: "qwen-token-plan".into(),
            source: ProviderQuotaSourceV1::LocalUsage,
            unit: Some(ProviderQuotaUnitV1::Tokens),
            used: Some(10),
            limit: Some(100),
            remaining: None,
            reset_at: None,
            observed_at: 1,
            availability: ProviderQuotaAvailabilityV1::Unknown,
            windows: Vec::new(),
        };
        assert_eq!(
            local.validate(),
            Err(ProviderQuotaProjectionError::InvalidLocalUsage)
        );
        let mut local_with_reset = local;
        local_with_reset.limit = None;
        local_with_reset.remaining = Some(1);
        assert_eq!(
            local_with_reset.validate(),
            Err(ProviderQuotaProjectionError::InvalidLocalUsage)
        );
        let mut unknown_with_timestamp = ProviderQuotaProjectionV1::unknown("zai");
        unknown_with_timestamp.observed_at = 1;
        assert_eq!(
            unknown_with_timestamp.validate(),
            Err(ProviderQuotaProjectionError::UnknownHasEvidence)
        );
    }

    #[test]
    fn provider_window_preserves_exhaustion_without_unit_or_limit() {
        let projection = ProviderQuotaProjectionV1 {
            provider_id: "zai".into(),
            source: ProviderQuotaSourceV1::ProviderReported,
            unit: None,
            used: None,
            limit: None,
            remaining: None,
            reset_at: None,
            observed_at: 10,
            availability: ProviderQuotaAvailabilityV1::Exhausted,
            windows: vec![ProviderQuotaWindowV1 {
                kind: "five_hour".into(),
                used: None,
                limit: None,
                remaining: Some(0),
                percent_used: None,
                reset_at: Some(20),
            }],
        };
        assert!(projection.validate().is_ok());
    }
}

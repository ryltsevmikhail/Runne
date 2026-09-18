use crate::{QuotaIdentity, QuotaModelError, QuotaSnapshot, QuotaWindow, QuotaWindowKind};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
struct RawIdentity {
    provider_id: String,
    credential_version: u64,
}

impl<'de> Deserialize<'de> for QuotaIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawIdentity::deserialize(deserializer)?;
        QuotaIdentity::new(raw.provider_id, raw.credential_version)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct RawWindow {
    kind: QuotaWindowKind,
    used: Option<u64>,
    limit: Option<u64>,
    remaining: Option<u64>,
    percent_used: Option<u8>,
    reset_at_unix_seconds: Option<u64>,
}

impl<'de> Deserialize<'de> for QuotaWindow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawWindow::deserialize(deserializer)?;
        QuotaWindow::new(
            raw.kind,
            raw.used,
            raw.limit,
            raw.remaining,
            raw.percent_used,
            raw.reset_at_unix_seconds,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct RawSnapshot {
    identity: QuotaIdentity,
    source: crate::QuotaObservationSource,
    observed_at_unix_seconds: u64,
    windows: Vec<QuotaWindow>,
}

impl<'de> Deserialize<'de> for QuotaSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSnapshot::deserialize(deserializer)?;
        QuotaSnapshot::new(
            raw.identity,
            raw.source,
            raw.observed_at_unix_seconds,
            raw.windows,
        )
        .map_err(|error: QuotaModelError| serde::de::Error::custom(error))
    }
}

use crate::{
    QuotaIdentity, QuotaModelError, QuotaObservationSource, QuotaSnapshot, QuotaWindow,
    QuotaWindowKind,
};
use serde::Deserialize;
use thiserror::Error;

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;

/// Bounded parser failure without provider body or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum QuotaParseError {
    /// Response body exceeded the parser bound.
    #[error("quota response exceeds parser bound")]
    BodyTooLarge,
    /// Response JSON was not a recognized object.
    #[error("quota response schema is unknown")]
    UnknownSchema,
    /// Recognized counters or percentage were invalid.
    #[error("quota response counters are invalid")]
    Invalid,
    /// Qwen quota is available through its console only.
    #[error("provider quota requires console refresh")]
    ConsoleRequired,
}

/// Parses the observed Z.ai internal `data.limits` response.
///
/// Percentages are preserved as percentages. Missing limits, remaining values,
/// and reset times are never derived from them.
pub fn parse_zai_limits(
    identity: QuotaIdentity,
    observed_at_unix_seconds: u64,
    body: &[u8],
) -> Result<QuotaSnapshot, QuotaParseError> {
    if body.is_empty() {
        return Err(QuotaParseError::UnknownSchema);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(QuotaParseError::BodyTooLarge);
    }
    let root = StrictValue::from_slice(body)?.0;
    let object = root.as_object().ok_or(QuotaParseError::UnknownSchema)?;
    if object
        .get("success")
        .is_some_and(|value| value.as_bool() != Some(true))
        || object
            .get("code")
            .is_some_and(|value| value.as_i64() != Some(0))
        || object.get("status").is_some_and(|value| {
            !value.as_str().is_some_and(|status| {
                status.eq_ignore_ascii_case("success") || status.eq_ignore_ascii_case("ok")
            }) && !value
                .as_u64()
                .is_some_and(|status| status == 0 || (200..300).contains(&status))
        })
    {
        return Err(QuotaParseError::UnknownSchema);
    }
    let data = object
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or(QuotaParseError::UnknownSchema)?;
    let array = data
        .get("limits")
        .and_then(serde_json::Value::as_array)
        .ok_or(QuotaParseError::UnknownSchema)?;
    let mut windows = Vec::new();
    for limit in array {
        let limit = limit.as_object().ok_or(QuotaParseError::UnknownSchema)?;
        let kind_name = limit
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or(QuotaParseError::UnknownSchema)?;
        let kind = match kind_name {
            "TOKENS_LIMIT" => QuotaWindowKind::TokenQuotaUnspecified,
            "TIME_LIMIT" => QuotaWindowKind::MonthlyTime,
            _ => continue,
        };
        let percentage = limit
            .get("percentage")
            .and_then(serde_json::Value::as_u64)
            .ok_or(QuotaParseError::UnknownSchema)?;
        let percentage = u8::try_from(percentage).map_err(|_| QuotaParseError::Invalid)?;
        windows.push(
            QuotaWindow::new(kind, None, None, None, Some(percentage), None)
                .map_err(|_| QuotaParseError::Invalid)?,
        );
    }
    if windows.is_empty() {
        return Err(QuotaParseError::UnknownSchema);
    }
    QuotaSnapshot::new(
        identity,
        QuotaObservationSource::ProviderApi,
        observed_at_unix_seconds,
        windows,
    )
    .map_err(|error| match error {
        QuotaModelError::EmptySnapshot => QuotaParseError::Invalid,
        _ => QuotaParseError::Invalid,
    })
}

pub(crate) struct StrictValue(pub(crate) serde_json::Value);

impl StrictValue {
    pub(crate) fn from_slice(body: &[u8]) -> Result<Self, QuotaParseError> {
        let mut deserializer = serde_json::Deserializer::from_slice(body);
        let value =
            Self::deserialize(&mut deserializer).map_err(|_| QuotaParseError::UnknownSchema)?;
        deserializer
            .end()
            .map_err(|_| QuotaParseError::UnknownSchema)?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON value without duplicate object keys")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictValue(serde_json::Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictValue(serde_json::Value::Number(value.into())))
            }
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictValue(serde_json::Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::Null))
            }
            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(serde_json::Value::Array(
                    values.into_iter().map(|v: StrictValue| v.0).collect(),
                )))
            }
            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut object = serde_json::Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if object.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(StrictValue(serde_json::Value::Object(object)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// Returns the explicit Qwen console-only posture; no REST quota call is made.
pub fn parse_qwen_token_plan() -> Result<QuotaSnapshot, QuotaParseError> {
    Err(QuotaParseError::ConsoleRequired)
}

/// Safe bounded retry-after evidence for an ambiguous rate-limit response.
pub fn parse_retry_after(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds = value.parse::<u64>().ok()?;
    (seconds <= MAX_RETRY_AFTER_SECONDS).then_some(seconds)
}

/// Classification for a provider error code, without retaining raw messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZaiErrorDisposition {
    /// Temporary request rate limit (1305).
    RateLimited,
    /// Known subscription usage exhaustion (1308 or 1310).
    Exhausted,
    /// Subscription plan has expired (1309).
    Expired,
    /// Account or plan is restricted (1313).
    Restricted,
    /// Code is not in the verified mapping.
    Unknown,
}

/// Maps only the verified Z.ai status codes.
pub const fn classify_zai_error_code(code: u16) -> ZaiErrorDisposition {
    match code {
        1305 => ZaiErrorDisposition::RateLimited,
        1308 | 1310 => ZaiErrorDisposition::Exhausted,
        1309 => ZaiErrorDisposition::Expired,
        1313 => ZaiErrorDisposition::Restricted,
        _ => ZaiErrorDisposition::Unknown,
    }
}

/// Extracts a structured Z.ai error code without retaining provider text.
pub fn parse_zai_error_code(body: &[u8]) -> Option<u16> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return None;
    }
    let root = StrictValue::from_slice(body).ok()?.0;
    let object = root.as_object()?;
    object
        .get("code")
        .or_else(|| {
            object
                .get("error")
                .and_then(serde_json::Value::as_object)?
                .get("code")
        })
        .and_then(serde_json::Value::as_u64)
        .and_then(|code| u16::try_from(code).ok())
}

/// Qwen 429 is ambiguous between burst and allocated plan quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QwenRateLimitEvidence {
    retry_after_seconds: Option<u64>,
}

impl QwenRateLimitEvidence {
    /// Classifies a 429 response without declaring permanent exhaustion.
    pub fn from_status(status: u16, retry_after: Option<&str>) -> Option<Self> {
        (status == 429).then_some(Self {
            retry_after_seconds: retry_after.and_then(parse_retry_after),
        })
    }
    /// Returns bounded retry-after evidence.
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

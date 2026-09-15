use crate::{QuotaIdentity, QuotaModelError, QuotaObservationSource};
use crate::{QuotaParseError, QuotaSnapshot, QuotaWindow, QuotaWindowKind, StrictValue};
use chrono::{DateTime, Utc};
use serde_json::Value;

const MAX_BODY_BYTES: usize = 256 * 1024;

/// Parses Kimi's managed usage response without deriving a total quota.
pub fn parse_kimi_usage(
    identity: QuotaIdentity,
    observed_at: u64,
    body: &[u8],
) -> Result<QuotaSnapshot, QuotaParseError> {
    let root = object(body)?;
    let mut windows = Vec::new();
    if let Some(usage) = root.get("usage").and_then(Value::as_object) {
        windows.push(kimi_window(usage, QuotaWindowKind::WeeklyTime)?);
    }
    if let Some(limits) = root.get("limits").and_then(Value::as_array) {
        for item in limits {
            let item = item.as_object().ok_or(QuotaParseError::UnknownSchema)?;
            let detail = item
                .get("detail")
                .and_then(Value::as_object)
                .ok_or(QuotaParseError::UnknownSchema)?;
            let kind = kimi_window_kind(item.get("window"));
            windows.push(kimi_window(detail, kind)?);
        }
    }
    if windows.is_empty() {
        return Err(QuotaParseError::UnknownSchema);
    }
    snapshot(identity, observed_at, windows)
}

fn kimi_window(
    object: &serde_json::Map<String, Value>,
    kind: QuotaWindowKind,
) -> Result<QuotaWindow, QuotaParseError> {
    let used = number_string(object.get("used"))?;
    let limit = number_string(object.get("limit"))?;
    let remaining = limit.and_then(|total| used.and_then(|used| total.checked_sub(used)));
    let reset = object
        .get("resetTime")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339);
    QuotaWindow::new(kind, used, limit, remaining, None, reset)
        .map_err(|_| QuotaParseError::Invalid)
}

/// Parses the official MiniMax token-plan remaining response for one model.
pub fn parse_minimax_quota(
    identity: QuotaIdentity,
    observed_at: u64,
    body: &[u8],
    model_name: &str,
) -> Result<QuotaSnapshot, QuotaParseError> {
    let root = object(body)?;
    if root
        .get("base_resp")
        .and_then(Value::as_object)
        .and_then(|base| base.get("status_code"))
        .and_then(Value::as_u64)
        != Some(0)
    {
        return Err(QuotaParseError::UnknownSchema);
    }
    let entries = root
        .get("model_remains")
        .and_then(Value::as_array)
        .ok_or(QuotaParseError::UnknownSchema)?;
    let entry = entries
        .iter()
        .find(|item| item.get("model_name").and_then(Value::as_str) == Some(model_name))
        .and_then(Value::as_object)
        .ok_or(QuotaParseError::UnknownSchema)?;
    let interval = minimax_window(
        entry,
        "current_interval",
        QuotaWindowKind::TokenQuotaUnspecified,
        "end_time",
    )?;
    let weekly = minimax_window(
        entry,
        "current_weekly",
        QuotaWindowKind::WeeklyTime,
        "weekly_end_time",
    )?;
    snapshot(identity, observed_at, vec![interval, weekly])
}

fn kimi_window_kind(value: Option<&Value>) -> QuotaWindowKind {
    let Some(window) = value.and_then(Value::as_object) else {
        return QuotaWindowKind::TokenQuotaUnspecified;
    };
    match (
        window.get("duration").and_then(Value::as_u64),
        window.get("timeUnit").and_then(Value::as_str),
    ) {
        (Some(300), Some("TIME_UNIT_MINUTE")) | (Some(5), Some("TIME_UNIT_HOUR")) => {
            QuotaWindowKind::FiveHourTime
        }
        (Some(7), Some("TIME_UNIT_DAY")) | (Some(1), Some("TIME_UNIT_WEEK")) => {
            QuotaWindowKind::WeeklyTime
        }
        _ => QuotaWindowKind::TokenQuotaUnspecified,
    }
}

fn minimax_window(
    entry: &serde_json::Map<String, Value>,
    prefix: &str,
    kind: QuotaWindowKind,
    reset_key: &str,
) -> Result<QuotaWindow, QuotaParseError> {
    let status = entry
        .get(&format!("{prefix}_status"))
        .and_then(Value::as_u64);
    let total = entry
        .get(&format!("{prefix}_total_count"))
        .and_then(Value::as_u64);
    let count = entry
        .get(&format!("{prefix}_usage_count"))
        .and_then(Value::as_u64);
    let percent = entry
        .get(&format!("{prefix}_remaining_percent"))
        .and_then(Value::as_u64);
    let (used, limit, remaining) = if status == Some(2) {
        (None, total.filter(|value| *value > 0), Some(0))
    } else if status == Some(3) || percent.is_none() {
        (None, None, None)
    } else {
        let percent = percent.filter(|value| *value <= 100);
        let remaining = match (count, total, percent) {
            (Some(count), Some(total), Some(percent)) if total > 0 && count <= total => {
                let as_remaining = count.checked_mul(100).map(|value| value / total);
                let as_used = (total - count).checked_mul(100).map(|value| value / total);
                let remaining_match = as_remaining
                    .filter(|value| value.abs_diff(percent) <= 1)
                    .map(|_| count);
                let used_match = as_used
                    .filter(|value| value.abs_diff(percent) <= 1)
                    .map(|_| total - count);
                match (remaining_match, used_match) {
                    (Some(left), Some(right)) if left == right => Some(left),
                    (Some(left), None) => Some(left),
                    (None, Some(right)) => Some(right),
                    _ => None,
                }
            }
            _ => None,
        };
        (
            remaining.and_then(|value| total.and_then(|total| total.checked_sub(value))),
            total,
            remaining,
        )
    };
    let reset = entry
        .get(reset_key)
        .and_then(Value::as_u64)
        .and_then(|value| (value > 0).then_some(value / 1000));
    QuotaWindow::new(kind, used, limit, remaining, None, reset)
        .map_err(|_| QuotaParseError::Invalid)
}

fn object(body: &[u8]) -> Result<serde_json::Map<String, Value>, QuotaParseError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(QuotaParseError::BodyTooLarge);
    }
    match StrictValue::from_slice(body)?.0 {
        Value::Object(object) => Ok(object),
        _ => Err(QuotaParseError::UnknownSchema),
    }
}

fn number_string(value: Option<&Value>) -> Result<Option<u64>, QuotaParseError> {
    let Some(value) = value else { return Ok(None) };
    let string = value.as_str().ok_or(QuotaParseError::UnknownSchema)?;
    if string.is_empty() || !string.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(QuotaParseError::Invalid);
    }
    string
        .parse()
        .map(Some)
        .map_err(|_| QuotaParseError::Invalid)
}

fn parse_rfc3339(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|date| u64::try_from(date.with_timezone(&Utc).timestamp()).ok())
        .filter(|value| *value > 0)
}

fn snapshot(
    identity: QuotaIdentity,
    observed_at: u64,
    windows: Vec<QuotaWindow>,
) -> Result<QuotaSnapshot, QuotaParseError> {
    QuotaSnapshot::new(
        identity,
        QuotaObservationSource::ProviderApi,
        observed_at,
        windows,
    )
    .map_err(|_: QuotaModelError| QuotaParseError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QuotaAvailability, QuotaProvider, QuotaRequestDescriptor};
    #[test]
    fn descriptors_use_verified_kimi_and_minimax_bearer_endpoints() {
        assert_eq!(
            QuotaRequestDescriptor::kimi_coding().provider(),
            QuotaProvider::KimiCoding
        );
        assert_eq!(
            QuotaRequestDescriptor::minimax().scope(),
            crate::QuotaEndpointScope::ProviderApi
        );
    }
    #[test]
    fn kimi_keeps_explicit_used_limit_and_reset() {
        let body = br#"{"usage":{"used":"40","limit":"1000","resetTime":"2026-09-14T00:00:00Z"}}"#;
        let snapshot =
            parse_kimi_usage(QuotaIdentity::new("kimi-coding", 1).unwrap(), 10, body).unwrap();
        assert_eq!(snapshot.availability(), QuotaAvailability::Known);
        assert_eq!(snapshot.windows()[0].remaining(), Some(960));
        assert!(snapshot.windows()[0].reset_at_unix_seconds().is_some());
    }

    #[test]
    fn kimi_preserves_verified_five_hour_and_weekly_windows() {
        let body = br#"{
          "limits":[
            {"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"used":"2","limit":"10","resetTime":"2026-09-14T00:00:00Z"}},
            {"window":{"duration":7,"timeUnit":"TIME_UNIT_DAY"},"detail":{"used":"4","limit":"20","resetTime":"2026-09-20T00:00:00Z"}}
          ]
        }"#;
        let snapshot =
            parse_kimi_usage(QuotaIdentity::new("kimi-coding", 1).unwrap(), 10, body).unwrap();
        assert_eq!(snapshot.windows()[0].kind(), QuotaWindowKind::FiveHourTime);
        assert_eq!(snapshot.windows()[1].kind(), QuotaWindowKind::WeeklyTime);
    }
    #[test]
    fn minimax_without_remaining_percent_stays_unknown() {
        let body = br#"{"base_resp":{"status_code":0},"model_remains":[{"model_name":"m","end_time":1776373200000,"current_interval_total_count":1500,"current_interval_usage_count":228,"current_weekly_total_count":0,"current_weekly_usage_count":0,"weekly_end_time":1776614400000}]}"#;
        let snapshot =
            parse_minimax_quota(QuotaIdentity::new("minimax", 1).unwrap(), 10, body, "m").unwrap();
        assert_eq!(snapshot.availability(), QuotaAvailability::Unknown);
        assert_eq!(snapshot.windows()[0].remaining(), None);
    }

    #[test]
    fn minimax_percent_resolves_counts_and_preserves_reset() {
        let body = br#"{"base_resp":{"status_code":0},"model_remains":[{"model_name":"m","end_time":1776373200000,"current_interval_total_count":1000,"current_interval_usage_count":500,"current_interval_remaining_percent":50,"current_weekly_total_count":5000,"current_weekly_usage_count":2000,"current_weekly_remaining_percent":60,"weekly_end_time":1776614400000}]}"#;
        let snapshot =
            parse_minimax_quota(QuotaIdentity::new("minimax", 1).unwrap(), 10, body, "m").unwrap();
        assert_eq!(snapshot.availability(), QuotaAvailability::Known);
        assert_eq!(snapshot.windows()[0].remaining(), Some(500));
        assert_eq!(
            snapshot.windows()[0].reset_at_unix_seconds(),
            Some(1_776_373_200)
        );
        assert_eq!(snapshot.windows()[1].kind(), QuotaWindowKind::WeeklyTime);
    }

    #[test]
    fn minimax_explicit_exhaustion_keeps_zero_without_fabricating_limit() {
        let body = br#"{"base_resp":{"status_code":0},"model_remains":[{"model_name":"m","current_interval_status":2,"current_weekly_status":3,"end_time":0,"weekly_end_time":0}]}"#;
        let snapshot =
            parse_minimax_quota(QuotaIdentity::new("minimax", 1).unwrap(), 10, body, "m").unwrap();
        assert_eq!(snapshot.availability(), QuotaAvailability::Exhausted);
        assert_eq!(snapshot.windows()[0].remaining(), Some(0));
        assert_eq!(snapshot.windows()[0].limit(), None);
    }

    #[test]
    fn minimax_zero_total_with_percent_is_unknown_without_division() {
        let body = br#"{"base_resp":{"status_code":0},"model_remains":[{"model_name":"m","current_interval_total_count":0,"current_interval_usage_count":0,"current_interval_remaining_percent":0,"current_weekly_total_count":0,"current_weekly_usage_count":0,"current_weekly_remaining_percent":0}]}"#;
        let snapshot =
            parse_minimax_quota(QuotaIdentity::new("minimax", 1).unwrap(), 10, body, "m").unwrap();
        assert_eq!(snapshot.availability(), QuotaAvailability::Unknown);
        assert_eq!(snapshot.windows()[0].remaining(), None);
    }

    #[test]
    fn minimax_rounded_percentage_tie_stays_unknown() {
        let body = br#"{"base_resp":{"status_code":0},"model_remains":[{"model_name":"m","current_interval_total_count":101,"current_interval_usage_count":50,"current_interval_remaining_percent":50,"current_weekly_total_count":101,"current_weekly_usage_count":50,"current_weekly_remaining_percent":50}]}"#;
        let snapshot =
            parse_minimax_quota(QuotaIdentity::new("minimax", 1).unwrap(), 10, body, "m").unwrap();
        assert_eq!(snapshot.windows()[0].remaining(), None);
    }
}

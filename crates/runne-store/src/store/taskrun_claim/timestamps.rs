use super::ClaimError;

pub(super) fn monotonic_event_time_us(
    now_ms: i64,
    previous_timestamp_us: i64,
) -> Result<i64, ClaimError> {
    now_ms
        .checked_mul(1000)
        .map(|floor_us| floor_us.max(previous_timestamp_us))
        .ok_or(ClaimError::CorruptData)
}

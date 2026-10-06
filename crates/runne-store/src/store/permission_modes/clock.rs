use std::time::{SystemTime, UNIX_EPOCH};

use super::model::PermissionModeStoreError;

pub(super) fn unix_ms() -> Result<i64, PermissionModeStoreError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?;
    i64::try_from(elapsed.as_millis())
        .ok()
        .filter(|value| *value > 0)
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)
}

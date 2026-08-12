use super::StoreOpenError;

pub const AFTER_PRIVATE_CREATE: &str = "after-private-create";
pub const AFTER_SNAPSHOT: &str = "after-snapshot";
pub const AFTER_FILE_DURABLE: &str = "after-file-durable";
pub const AFTER_PUBLISH: &str = "after-publish";
pub const AFTER_PUBLISH_DURABLE: &str = "after-publish-durable";
pub const BEFORE_MIGRATION: &str = "before-migration";
pub const INSIDE_MIGRATION: &str = "inside-migration";

#[cfg(feature = "test-support")]
std::thread_local! { static FAILPOINT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(feature = "test-support")]
pub fn set_failpoint(stage: Option<&'static str>) {
    FAILPOINT.with(|failpoint| failpoint.set(stage));
}

#[cfg(feature = "test-support")]
pub fn hit(stage: &str) -> Result<(), StoreOpenError> {
    if FAILPOINT.with(std::cell::Cell::get) == Some(stage) {
        return Err(StoreOpenError::PreV5BackupRecoveryRequired);
    }
    Ok(())
}

#[cfg(not(feature = "test-support"))]
pub const fn hit(stage: &str) -> Result<(), StoreOpenError> {
    if stage.is_empty() {
        return Err(StoreOpenError::PreV5BackupRecoveryRequired);
    }
    Ok(())
}

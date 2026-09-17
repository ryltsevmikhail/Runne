use std::sync::Arc;

use runne_api::LaunchAuthorityError;

#[cfg_attr(not(unix), allow(dead_code))]
pub(super) type TicketClock = Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) type QualificationClock =
    Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// Builds the continuous clock used by existing V3 renewal protocols.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn macos_continuous_ticket_clock() -> TicketClock {
    Arc::new(|| {
        runne_platform_desktop::MacOsContinuousClock::now_millis()
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)
    })
}

/// Builds the Unix epoch clock required by signed qualification timestamps.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unix_epoch_qualification_clock() -> QualificationClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| LaunchAuthorityError::StaleLaunchAuthority)
    })
}

/// Builds the wall-clock ticket clock for unix targets without a platform
/// continuous-clock facility. The enrollment TTLs are short (30 s), so the
/// same ceiling as the launch TTLs applies.
#[cfg(all(unix, not(all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) fn unix_wall_ticket_clock() -> TicketClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| LaunchAuthorityError::StaleLaunchAuthority)
    })
}

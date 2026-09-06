use std::sync::Arc;

use runne_api::LaunchAuthorityError;

pub(super) type TicketClock = Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;
pub(super) type QualificationClock =
    Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// Builds the continuous clock used by existing V3 renewal protocols.
pub(crate) fn macos_continuous_ticket_clock() -> TicketClock {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Arc::new(|| {
            runne_platform_desktop::MacOsContinuousClock::now_millis()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)
        })
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    Arc::new(|| Err(LaunchAuthorityError::RenewalUnavailable))
}

/// Builds the Unix epoch clock required by signed qualification timestamps.
pub(crate) fn unix_epoch_qualification_clock() -> QualificationClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| LaunchAuthorityError::StaleLaunchAuthority)
    })
}

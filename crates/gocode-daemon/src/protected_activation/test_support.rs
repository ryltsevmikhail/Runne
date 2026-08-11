//! Test-only control helpers that cannot construct a root admission issuer.

use super::*;

#[cfg(feature = "desktop-protected")]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_without_admission(
    channel: &mut ProtectedActivationChannel,
    frame: &[u8],
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV1,
    used: &mut std::collections::VecDeque<([u8; 16], [u8; 32], u64)>,
    previous: u64,
    now: u64,
) -> Result<Option<u64>, LaunchAuthorityError> {
    dispatch_root_handle_control_frame(channel, frame, keys, owned, used, previous, now, None)
}

#[cfg(feature = "desktop-protected")]
pub fn run_without_admission(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned: ProtectedOwnedLaunchV1,
    sessions: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    run_control_loop(channel, keys, owned, sessions, clock, None)
}

#[cfg(not(feature = "desktop-protected"))]
pub fn run_without_admission(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned: ProtectedOwnedLaunchV1,
    sessions: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    run_control_loop(channel, keys, owned, sessions, clock)
}

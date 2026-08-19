//! Test-only control helpers that cannot construct a root admission issuer.

#[cfg(test)]
use super::*;

#[cfg(feature = "desktop-protected")]
pub use super::test_root_admission_fixture::run_inherited_root_admission_fixture;

/// Runs the closed OpenAI loopback process fixture over inherited stdin.
#[cfg(feature = "desktop-protected")]
pub fn run_loopback_inherited_fixture() -> Result<(), crate::error::DaemonError> {
    super::loopback_fixture::run_inherited_channel()
}

#[cfg(feature = "desktop-protected")]
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn dispatch_without_admission(
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
#[cfg(test)]
pub(crate) fn run_without_admission(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned: ProtectedOwnedLaunchV1,
    sessions: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    run_control_loop(channel, keys, owned, sessions, clock, None)
}

#[cfg(not(feature = "desktop-protected"))]
#[cfg(test)]
pub(crate) fn run_without_admission(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned: ProtectedOwnedLaunchV1,
    sessions: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    run_control_loop(channel, keys, owned, sessions, clock)
}

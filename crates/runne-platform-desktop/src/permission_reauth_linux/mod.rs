//! Linux native warning and OS reauthentication primitives for protected permission control.

mod native_consent;
mod native_warning_linux;
mod policy;

#[cfg(test)]
mod tests;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

pub(crate) use native_consent::native_confirmation_binding_digest;
#[cfg(feature = "test-support")]
pub(crate) use native_warning_linux::mock_native_permission_warning_confirmation;
pub use native_warning_linux::{
    NativePermissionWarningConfirmationV1, NativePermissionWarningMainThreadScheduler,
    NativePermissionWarningUiTask, request_native_permission_warning,
};
pub use runne_linux_pam::{
    FreshOsReauthentication, MAX_REAUTH_WINDOW, PamCancellation, PamConversationHandler,
    PamInteractionError, PamMessageKind, ReauthenticationError, VerifiedPamFacts,
};

static NATIVE_REAUTH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Qualifies host policy, performs native PAM reauthentication, then rechecks for drift.
///
/// # Errors
/// Returns an error for invalid bindings, expired deadlines, rejected policy, or PAM worker failure.
pub fn reauthenticate(
    challenge_digest: [u8; 32],
    deadline: Instant,
    handler: Arc<dyn PamConversationHandler>,
) -> Result<FreshOsReauthentication, LinuxReauthenticationError> {
    if challenge_digest == [0; 32] {
        return Err(LinuxReauthenticationError::InvalidBinding);
    }
    runne_linux_pam::validate_deadline(deadline).map_err(LinuxReauthenticationError::Pam)?;
    let policy = policy::qualify().map_err(|()| LinuxReauthenticationError::PolicyRejected)?;
    runne_linux_pam::validate_deadline(deadline).map_err(LinuxReauthenticationError::Pam)?;
    if policy.digest() == [0; 32] {
        return Err(LinuxReauthenticationError::InvalidBinding);
    }
    let guard = NativeFlightGuard::acquire()?;
    let cancellation = PamCancellation::new();
    let worker_cancellation = cancellation.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawn = thread::Builder::new()
        .name("runne-linux-pam".into())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                policy::verify_unchanged(&policy)
                    .map_err(|()| LinuxReauthenticationError::PolicyRejected)?;
                let token = runne_linux_pam::reauthenticate(
                    challenge_digest,
                    policy.digest(),
                    deadline,
                    &worker_cancellation,
                    handler,
                )
                .map_err(LinuxReauthenticationError::Pam)?;
                policy::verify_unchanged(&policy)
                    .map_err(|()| LinuxReauthenticationError::PolicyRejected)?;
                if Instant::now() >= deadline {
                    return Err(LinuxReauthenticationError::Expired);
                }
                Ok(token)
            }))
            .unwrap_or(Err(LinuxReauthenticationError::WorkerFailed));
            drop(guard);
            let _ = sender.send(outcome);
        });
    if spawn.is_err() {
        cancellation.cancel();
        return Err(LinuxReauthenticationError::WorkerFailed);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(Ok(token)) if Instant::now() < deadline => Ok(token),
        Ok(Ok(_)) | Err(mpsc::RecvTimeoutError::Timeout) => {
            cancellation.cancel();
            Err(LinuxReauthenticationError::Expired)
        }
        Ok(Err(error)) => Err(error),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(LinuxReauthenticationError::WorkerFailed),
    }
}

/// Consumes fresh PAM evidence against the currently qualified host policy.
///
/// # Errors
/// Returns an error if policy qualification or challenge-bound token consumption fails.
pub fn consume_verified(
    token: FreshOsReauthentication,
    challenge_digest: [u8; 32],
) -> Result<VerifiedPamFacts, LinuxReauthenticationError> {
    let current = policy::qualify().map_err(|()| LinuxReauthenticationError::PolicyRejected)?;
    token
        .consume_verified(challenge_digest, current.digest())
        .map_err(LinuxReauthenticationError::Pam)
}

/// Non-secret error categories for native qualification and worker lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxReauthenticationError {
    Expired,
    Pam(ReauthenticationError),
    InvalidBinding,
    PolicyRejected,
    Busy,
    WorkerFailed,
    NativeWarningRejected,
}

impl std::fmt::Display for LinuxReauthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Expired => "Linux reauthentication deadline expired",
            Self::Pam(_) => "Linux PAM reauthentication failed",
            Self::InvalidBinding => "Linux reauthentication binding is invalid",
            Self::PolicyRejected => "Linux PAM policy is unknown or changed",
            Self::Busy => "another Linux reauthentication is active",
            Self::WorkerFailed => "Linux reauthentication worker failed",
            Self::NativeWarningRejected => "native permission warning was not continued",
        })
    }
}

impl std::error::Error for LinuxReauthenticationError {}

struct NativeFlightGuard;

impl NativeFlightGuard {
    fn acquire() -> Result<Self, LinuxReauthenticationError> {
        NATIVE_REAUTH_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| LinuxReauthenticationError::Busy)
    }
}

impl Drop for NativeFlightGuard {
    fn drop(&mut self) {
        NATIVE_REAUTH_ACTIVE.store(false, Ordering::Release);
    }
}

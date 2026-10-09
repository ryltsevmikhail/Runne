use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::conversation::{ConversationState, PamConversationHandler, pam_conversation};
use crate::ffi::{self, PamConversation, PamSession};
use crate::identity;
use crate::types::{FreshOsReauthentication, PamCancellation, ReauthenticationError};

static PAM_TRANSACTION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Performs authentication and account validation in one bounded PAM transaction.
///
/// # Errors
///
/// Returns an error when identity, the native conversation, PAM auth/account checks,
/// cancellation, or the monotonic deadline fails.
pub fn reauthenticate(
    challenge_digest: [u8; 32],
    qualified_policy_digest: [u8; 32],
    deadline: Instant,
    cancellation: &PamCancellation,
    handler: Arc<dyn PamConversationHandler>,
) -> Result<FreshOsReauthentication, ReauthenticationError> {
    validate_binding(challenge_digest, qualified_policy_digest)?;
    super::types::validate_deadline(deadline)?;
    let _flight = FlightGuard::acquire()?;
    ensure_live(deadline, cancellation)?;
    let uid = identity::current_uid()?;
    let username = identity::username_for_uid(uid)?;
    let mut conversation_state = Box::new(ConversationState::new(
        handler,
        (*cancellation).clone(),
        deadline,
    ));
    let app_data = (&raw mut *conversation_state).cast::<c_void>();
    let conversation = PamConversation {
        conv: Some(pam_conversation),
        appdata_ptr: app_data,
    };
    let mut session = PamSession::start(&username, &conversation)
        .map_err(|_| ReauthenticationError::PamRejected)?;
    ensure_live(deadline, cancellation)?;
    let auth_status = session.authenticate();
    ensure_live(deadline, cancellation)?;
    if auth_status != ffi::PAM_SUCCESS {
        return Err(ReauthenticationError::PamRejected);
    }
    require_interaction(
        conversation_state.echo_off_count(),
        conversation_state.cancelled(),
        conversation_state.rejected() || conversation_state.panicked(),
    )?;
    let account_status = session.account_management();
    ensure_live(deadline, cancellation)?;
    require_successful_interaction(
        auth_status,
        account_status,
        conversation_state.echo_off_count(),
        conversation_state.cancelled(),
        conversation_state.rejected() || conversation_state.panicked(),
    )?;
    let pam_user = session
        .pam_user()
        .map_err(|()| ReauthenticationError::IdentityUnavailable)?;
    identity::verify_pam_user(&pam_user, uid)?;
    if identity::current_uid()? != uid {
        return Err(ReauthenticationError::IdentityUnavailable);
    }
    ensure_live(deadline, cancellation)?;
    if session.finish() != ffi::PAM_SUCCESS {
        return Err(ReauthenticationError::PamRejected);
    }
    let completed_at = Instant::now();
    ensure_live(deadline, cancellation)?;
    let authenticated_at_unix_ms = capture_authenticated_at_unix_ms(SystemTime::now())?;
    ensure_live(deadline, cancellation)?;
    Ok(FreshOsReauthentication::verified(
        challenge_digest,
        uid,
        qualified_policy_digest,
        authenticated_at_unix_ms,
        deadline,
        completed_at,
    ))
}

fn capture_authenticated_at_unix_ms(now: SystemTime) -> Result<u64, ReauthenticationError> {
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReauthenticationError::ClockUnavailable)?;
    let millis = since_epoch.as_millis();
    if millis == 0 || millis > u128::from(u64::MAX) {
        return Err(ReauthenticationError::ClockUnavailable);
    }
    u64::try_from(millis).map_err(|_| ReauthenticationError::ClockUnavailable)
}

fn validate_binding(
    challenge_digest: [u8; 32],
    qualified_policy_digest: [u8; 32],
) -> Result<(), ReauthenticationError> {
    if challenge_digest == [0; 32] || qualified_policy_digest == [0; 32] {
        return Err(ReauthenticationError::TokenMismatch);
    }
    Ok(())
}

fn ensure_live(
    deadline: Instant,
    cancellation: &PamCancellation,
) -> Result<(), ReauthenticationError> {
    if Instant::now() >= deadline {
        return Err(ReauthenticationError::Expired);
    }
    if cancellation.is_cancelled() {
        return Err(ReauthenticationError::Cancelled);
    }
    Ok(())
}

fn require_successful_interaction(
    auth_status: i32,
    account_status: i32,
    echo_off_count: usize,
    cancelled: bool,
    rejected: bool,
) -> Result<(), ReauthenticationError> {
    require_interaction(echo_off_count, cancelled, rejected)?;
    if auth_status != ffi::PAM_SUCCESS || account_status != ffi::PAM_SUCCESS {
        return Err(ReauthenticationError::PamRejected);
    }
    Ok(())
}

const fn require_interaction(
    echo_off_count: usize,
    cancelled: bool,
    rejected: bool,
) -> Result<(), ReauthenticationError> {
    if cancelled {
        return Err(ReauthenticationError::Cancelled);
    }
    if rejected || echo_off_count != 1 {
        return Err(ReauthenticationError::InteractionRejected);
    }
    Ok(())
}

struct FlightGuard;

impl FlightGuard {
    fn acquire() -> Result<Self, ReauthenticationError> {
        PAM_TRANSACTION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| ReauthenticationError::Busy)
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        PAM_TRANSACTION_ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(test)]
pub fn test_require_successful_interaction(
    auth_status: i32,
    account_status: i32,
    echo_off_count: usize,
    rejected: bool,
) -> Result<(), ReauthenticationError> {
    require_successful_interaction(auth_status, account_status, echo_off_count, false, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn zero_challenge_or_policy_digest_is_rejected_before_pam() {
        assert_eq!(
            validate_binding([0; 32], [1; 32]),
            Err(ReauthenticationError::TokenMismatch)
        );
        assert_eq!(
            validate_binding([1; 32], [0; 32]),
            Err(ReauthenticationError::TokenMismatch)
        );
        assert_eq!(validate_binding([1; 32], [2; 32]), Ok(()));
    }

    #[test]
    fn authentication_timestamp_rejects_unknown_zero_and_out_of_range_clock_values() {
        assert_eq!(
            capture_authenticated_at_unix_ms(UNIX_EPOCH),
            Err(ReauthenticationError::ClockUnavailable)
        );
        assert_eq!(
            capture_authenticated_at_unix_ms(UNIX_EPOCH + Duration::from_nanos(1)),
            Err(ReauthenticationError::ClockUnavailable)
        );
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond before epoch is representable");
        assert_eq!(
            capture_authenticated_at_unix_ms(before_epoch),
            Err(ReauthenticationError::ClockUnavailable)
        );
        let max_timestamp = UNIX_EPOCH
            .checked_add(Duration::from_millis(u64::MAX))
            .expect("test timestamp is representable");
        assert_eq!(
            capture_authenticated_at_unix_ms(max_timestamp),
            Ok(u64::MAX)
        );
        let out_of_range = max_timestamp
            .checked_add(Duration::from_millis(1))
            .expect("out-of-range test timestamp is representable");
        assert_eq!(
            capture_authenticated_at_unix_ms(out_of_range),
            Err(ReauthenticationError::ClockUnavailable)
        );
        assert_eq!(
            capture_authenticated_at_unix_ms(UNIX_EPOCH + Duration::from_millis(42)),
            Ok(42)
        );
    }
}

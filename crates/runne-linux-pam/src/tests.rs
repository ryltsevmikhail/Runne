use std::time::{Duration, Instant};

use super::ffi::PAM_SUCCESS;
use super::transaction::test_require_successful_interaction;
use super::{FreshOsReauthentication, MAX_REAUTH_WINDOW, ReauthenticationError, validate_deadline};

#[test]
fn deadlines_must_be_future_and_bounded() {
    let unbounded = Instant::now() + MAX_REAUTH_WINDOW + Duration::from_secs(1);
    assert_eq!(
        validate_deadline(unbounded),
        Err(ReauthenticationError::Expired)
    );
    assert!(validate_deadline(Instant::now() + Duration::from_secs(1)).is_ok());
    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("instant is nonzero");
    assert_eq!(
        validate_deadline(expired),
        Err(ReauthenticationError::Expired)
    );
}

#[test]
fn success_without_a_real_echo_off_conversation_is_rejected() {
    assert_eq!(
        test_require_successful_interaction(PAM_SUCCESS, PAM_SUCCESS, 0, false),
        Err(ReauthenticationError::InteractionRejected)
    );
    assert_eq!(
        test_require_successful_interaction(PAM_SUCCESS, PAM_SUCCESS, 2, false),
        Err(ReauthenticationError::InteractionRejected)
    );
}

#[test]
fn authentication_and_account_failures_do_not_create_success() {
    assert_eq!(
        test_require_successful_interaction(9, PAM_SUCCESS, 1, false),
        Err(ReauthenticationError::PamRejected)
    );
    assert_eq!(
        test_require_successful_interaction(PAM_SUCCESS, 12, 1, false),
        Err(ReauthenticationError::PamRejected)
    );
}

#[test]
fn token_is_move_only_and_binds_challenge_uid_policy_and_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(3);
    let token = FreshOsReauthentication::test_fixture([1; 32], 1000, [2; 32], 1, deadline, now);
    assert!(matches!(
        token.test_validate_for([9; 32], 1000, [2; 32], now),
        Err(ReauthenticationError::TokenMismatch)
    ));

    let token = FreshOsReauthentication::test_fixture([1; 32], 1000, [2; 32], 1, deadline, now);
    assert!(matches!(
        token.test_validate_for([1; 32], 1001, [2; 32], now),
        Err(ReauthenticationError::TokenMismatch)
    ));

    let token = FreshOsReauthentication::test_fixture([1; 32], 1000, [2; 32], 1, deadline, now);
    assert!(matches!(
        token.test_validate_for([1; 32], 1000, [3; 32], now),
        Err(ReauthenticationError::TokenMismatch)
    ));

    let token = FreshOsReauthentication::test_fixture([1; 32], 1000, [2; 32], 1, deadline, now);
    assert!(matches!(
        token.test_validate_for([1; 32], 1000, [2; 32], deadline),
        Err(ReauthenticationError::Expired)
    ));

    let token = FreshOsReauthentication::test_fixture([1; 32], 1000, [2; 32], 1, deadline, now);
    assert!(matches!(
        token.test_validate_for(
            [1; 32],
            1000,
            [2; 32],
            now.checked_sub(Duration::from_nanos(1))
                .expect("nonzero instant"),
        ),
        Err(ReauthenticationError::Expired)
    ));
}

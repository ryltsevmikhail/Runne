use std::time::{Duration, Instant};

use super::{FreshOsReauthentication, ReauthenticationError, VerifiedPamFacts};

const _: fn(FreshOsReauthentication, [u8; 32], [u8; 32]) -> Result<(), ReauthenticationError> =
    FreshOsReauthentication::consume;
const _: fn(
    FreshOsReauthentication,
    [u8; 32],
    [u8; 32],
) -> Result<VerifiedPamFacts, ReauthenticationError> = FreshOsReauthentication::consume_verified;

const CHALLENGE: [u8; 32] = [0x31; 32];
const FINGERPRINT: [u8; 32] = [0x72; 32];
const AUTHENTICATED_AT_UNIX_MS: u64 = 1_800_000_000_123;

fn token_fixture(now: Instant, deadline: Instant) -> FreshOsReauthentication {
    // Explicit mock fixture: this does not invoke PAM or claim a real authentication.
    FreshOsReauthentication::test_fixture(
        CHALLENGE,
        41_002,
        FINGERPRINT,
        AUTHENTICATED_AT_UNIX_MS,
        deadline,
        now,
    )
}

#[test]
fn validated_consumption_returns_the_exact_immutable_worker_facts() {
    let now = Instant::now();
    let facts = token_fixture(now, now + Duration::from_secs(20))
        .test_validate_for(CHALLENGE, 41_002, FINGERPRINT, now)
        .expect("matching live token");

    assert_eq!(facts.challenge_digest(), CHALLENGE);
    assert_eq!(facts.uid(), 41_002);
    assert_eq!(facts.qualified_fingerprint(), FINGERPRINT);
    assert_eq!(facts.authenticated_at_unix_ms(), AUTHENTICATED_AT_UNIX_MS);
}

#[test]
fn wrong_challenge_uid_or_qualified_fingerprint_rejects_facts() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(20);
    assert!(matches!(
        token_fixture(now, deadline).test_validate_for([0x32; 32], 41_002, FINGERPRINT, now),
        Err(ReauthenticationError::TokenMismatch)
    ));
    assert!(matches!(
        token_fixture(now, deadline).test_validate_for(CHALLENGE, 41_003, FINGERPRINT, now),
        Err(ReauthenticationError::TokenMismatch)
    ));
    assert!(matches!(
        token_fixture(now, deadline).test_validate_for(CHALLENGE, 41_002, [0x73; 32], now),
        Err(ReauthenticationError::TokenMismatch)
    ));
}

#[test]
fn token_expiry_is_checked_at_the_exact_monotonic_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(20);
    assert!(matches!(
        token_fixture(now, deadline).test_validate_for(CHALLENGE, 41_002, FINGERPRINT, deadline),
        Err(ReauthenticationError::Expired)
    ));
    let before_completion = now
        .checked_sub(Duration::from_nanos(1))
        .expect("test instant is representable");
    assert!(matches!(
        token_fixture(now, deadline).test_validate_for(
            CHALLENGE,
            41_002,
            FINGERPRINT,
            before_completion,
        ),
        Err(ReauthenticationError::Expired)
    ));
}

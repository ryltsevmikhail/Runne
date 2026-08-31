use super::{CredentialEnrollmentError, RawCredentialTicket, generate_ticket_with};

#[test]
fn credential_enrollment_review_ticket_entropy_failure_is_fail_closed() {
    let result = generate_ticket_with(|_| Err(()));
    assert!(matches!(
        result,
        Err(CredentialEnrollmentError::EntropyUnavailable)
    ));
}

#[test]
fn credential_enrollment_review_ticket_rejects_non_random_zero_output() {
    let result = generate_ticket_with(|_| Ok(()));
    assert!(matches!(
        result,
        Err(CredentialEnrollmentError::EntropyUnavailable)
    ));
}

#[test]
fn credential_enrollment_review_ticket_generation_uses_internal_entropy() {
    assert!(RawCredentialTicket::generate().is_ok());
}

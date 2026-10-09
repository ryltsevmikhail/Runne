// Pure validation only. This fixture never opens a native dialog or creates a confirmation token.
use super::*;

#[test]
fn approval_and_denial_require_visible_active_unexpired_accept() {
    for decision in [ApprovalDecisionDto::Approve, ApprovalDecisionDto::Deny] {
        assert_eq!(
            decision_button(decision),
            match decision {
                ApprovalDecisionDto::Approve => "Confirm approve",
                ApprovalDecisionDto::Deny => "Confirm deny",
            }
        );
        assert!(response_authorizes(
            gtk::ResponseType::Accept,
            true,
            true,
            Some(100),
            101
        ));
    }
}

#[test]
fn cancel_close_expiry_inactive_and_hidden_accept_fail_closed() {
    assert!(!response_authorizes(
        gtk::ResponseType::Cancel,
        true,
        true,
        Some(100),
        101
    ));
    assert!(!response_authorizes(
        gtk::ResponseType::DeleteEvent,
        true,
        true,
        Some(100),
        101
    ));
    assert!(!response_authorizes(
        gtk::ResponseType::Accept,
        false,
        true,
        Some(100),
        101
    ));
    assert!(!response_authorizes(
        gtk::ResponseType::Accept,
        true,
        false,
        Some(100),
        101
    ));
    assert!(!response_authorizes(
        gtk::ResponseType::Accept,
        true,
        true,
        Some(101),
        101
    ));
    assert!(!response_authorizes(
        gtk::ResponseType::Accept,
        true,
        true,
        None,
        101
    ));
}

#[test]
fn disclosure_escapes_controls_and_bidi_overrides_as_visible_text() {
    assert_eq!(
        escape_bidi_and_controls("safe\u{202e}txt\nnext"),
        "safe\\u{202E}txt\\u{000A}next"
    );
}

#[test]
fn review_rejects_nonpositive_deadline_or_oversized_input() {
    let mut review = LinuxApprovalReview {
        approval_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000001").unwrap(),
        task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000002").unwrap(),
        attempt_id: None,
        invocation_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000003").unwrap(),
        command_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000004").unwrap(),
        action: "file.create".to_owned(),
        resource: "workspace:/new.txt".to_owned(),
        risk_summary: "create a file".to_owned(),
        action_digest: [1; 32],
        policy_revision: 7,
        request_version: 3,
        approval_generation: 4,
        decision: ApprovalDecisionDto::Approve,
        digest: [1; 32],
        expires_at_unix_ms: 100,
    };
    assert!(review.validate().is_ok());
    review.expires_at_unix_ms = 0;
    assert_eq!(
        review.validate(),
        Err(ApprovalConfirmationError::InvalidReview)
    );
    review.expires_at_unix_ms = 100;
    review.action = "x".repeat(MAX_DISCLOSURE_BYTES + 1);
    assert_eq!(
        review.validate(),
        Err(ApprovalConfirmationError::InvalidReview)
    );
}

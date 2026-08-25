use runne_api::{ApprovalDecision, ApprovalState, ApprovalSummary, ApprovalValidationError};
use runne_domain::id::{ApprovalId, AttemptId, InvocationId, TaskRunId};

const ID: &str = "018f2e3a-7000-7000-8000-000000000212";

fn summary() -> ApprovalSummary {
    ApprovalSummary::try_new(
        ID.parse::<ApprovalId>().expect("approval id"),
        ID.parse::<TaskRunId>().expect("task run id"),
        Some(ID.parse::<AttemptId>().expect("attempt id")),
        ID.parse::<InvocationId>().expect("invocation id"),
        "fs:write",
        "workspace:/src/main.rs",
        [0x11; 32],
        7,
        3,
        2_000,
        "Write one source file",
    )
    .expect("valid approval")
}

#[test]
fn approval_summary_is_safe_and_decidable_only_when_pending() {
    let value = summary();
    assert_eq!(value.state(), ApprovalState::Pending);
    assert!(value.requires_decision());
    assert_eq!(ApprovalDecision::Approve.as_str(), "approve");
    assert_eq!(ApprovalDecision::Deny.as_str(), "deny");
}

#[test]
fn approval_summary_rejects_control_or_oversized_display_data() {
    for action in ["", "fs:write\nsecret", &"x".repeat(4097)] {
        let error = ApprovalSummary::try_new(
            ID.parse().unwrap(),
            ID.parse().unwrap(),
            None,
            ID.parse().unwrap(),
            action,
            "workspace:/src/main.rs",
            [0x11; 32],
            7,
            3,
            2_000,
            "safe summary",
        )
        .expect_err("unsafe action must fail");
        assert_eq!(error, ApprovalValidationError::InvalidDisplayData);
    }
}

#[test]
fn approval_summary_rejects_invalid_version_and_expiry() {
    let error = ApprovalSummary::try_new(
        ID.parse().unwrap(),
        ID.parse().unwrap(),
        None,
        ID.parse().unwrap(),
        "fs:write",
        "workspace:/src/main.rs",
        [0x11; 32],
        0,
        0,
        2_000,
        "safe summary",
    )
    .expect_err("zero versions must fail");
    assert_eq!(error, ApprovalValidationError::InvalidVersion);
}

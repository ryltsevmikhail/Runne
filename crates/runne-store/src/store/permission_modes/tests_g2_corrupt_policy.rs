//! Staged Linux guest-only candidates. No registration or execution authorization.
#[path = "tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_g2_corrupt_policy/approval_flow.rs"]
mod approval_flow;
#[path = "tests_g2_corrupt_policy/assertions.rs"]
mod assertions;
#[path = "tests_g2_corrupt_policy/fault.rs"]
mod fault;
#[path = "tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "tests_g2_corrupt_policy/flow.rs"]
mod flow;
#[path = "tests_g2_corrupt_policy/lifecycle.rs"]
mod lifecycle;
#[path = "tests_g2_corrupt_policy/owned.rs"]
mod owned;
#[path = "tests_capture_retention/target.rs"]
mod target;
#[path = "tests_shell_corpus/terminal.rs"]
mod terminal;

#[test]
fn missing_current_policy_row_denies_public_go_before_burn() {
    flow::run(true);
}

#[test]
fn intact_current_policy_fresh_control_reaches_factual_public_terminal() {
    flow::run(false);
}

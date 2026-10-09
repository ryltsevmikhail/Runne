use super::*;
use runne_application::ports::RuntimeAuthorityId;
use runne_domain::id::{ApprovalId, InvocationId, TaskRunId};
use runne_store::ProjectWorkspaceStore;
use std::io::Write as _;

#[path = "approval_crash/consent.rs"]
mod consent;
#[path = "approval_crash/crash_case.rs"]
mod crash_case;

pub use consent::execute_with_mock_consent;
use consent::*;
use crash_case::*;

#[test]
fn protected_cli_approval_process_crashes_replay_exactly_without_repost() {
    let before_post = run_crash_case("approval_before_post");
    let after_commit = run_crash_case("approval_after_commit");
    assert_ne!(
        before_post.0, after_commit.0,
        "approval roots use independent IDs"
    );
    assert_ne!(
        before_post.1, after_commit.1,
        "approval roots use independent commands"
    );
}

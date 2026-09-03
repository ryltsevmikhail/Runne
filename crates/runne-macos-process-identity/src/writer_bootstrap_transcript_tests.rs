#[path = "writer_bootstrap_transcript_tests/deadline.rs"]
mod deadline;
#[path = "writer_bootstrap_transcript_tests/prefix.rs"]
mod prefix;
#[path = "writer_bootstrap_transcript_tests/support.rs"]
mod support;

#[test]
fn local_test_opt_in_extends_only_the_bootstrap_wait_budget() {
    assert_eq!(
        super::prefix_budget_for_local_test_opt_in(true),
        std::time::Duration::from_mins(2)
    );
    assert_eq!(
        super::prefix_budget_for_local_test_opt_in(false),
        std::time::Duration::from_secs(1)
    );
}

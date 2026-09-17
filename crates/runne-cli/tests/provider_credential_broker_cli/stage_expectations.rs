//! Exact fail-closed stderr expectations for the broker CLI tests.
//!
//! Default production builds are silent: a fail-closed broker exit prints
//! exactly the generic operation-failed line on stderr. Builds with the
//! `local-native-enrollment-test` feature additionally emit the audited fixed
//! writer-stage markers (see `writer_stage_live.rs`) before the same final
//! line. Every expectation is the complete stderr string, so the fail-closed
//! assertion keeps rejecting arbitrary additional output in both builds.

use std::os::unix::process::ExitStatusExt as _;
use std::process::{ExitStatus, Output};

use super::{OPERATION_FAILED, assert_closed};

/// Audited writer-stage marker vocabulary from `writer_stage_live.rs`.
const AUDITED_MARKERS: &[&str] = &[
    "writer-stage=secret-inspect",
    "writer-stage=endpoint-receive",
    "writer-stage=session-observe",
    "writer-stage=authenticated-run",
    "writer-stage-failed=secret-inspect",
    "writer-stage-failed=endpoint-receive",
    "writer-stage-failed=session-observe",
    "writer-stage-failed=authenticated-run",
];

/// Complete expected stderr when the broker fails closed because the daemon
/// endpoint handoff receive stage failed.
#[cfg(feature = "local-native-enrollment-test")]
pub const ENDPOINT_RECEIVE_FAILED: &str = "writer-stage=secret-inspect\nwriter-stage=endpoint-receive\nwriter-stage-failed=endpoint-receive\nprovider credential operation failed\n";

/// Complete expected stderr when the broker fails closed because the pinned
/// writer session observation stage failed.
#[cfg(feature = "local-native-enrollment-test")]
pub const SESSION_OBSERVE_FAILED: &str = "writer-stage=secret-inspect\nwriter-stage=endpoint-receive\nwriter-stage=session-observe\nwriter-stage-failed=session-observe\nprovider credential operation failed\n";

/// Silent production twins: fail-closed stderr is exactly the generic line.
#[cfg(not(feature = "local-native-enrollment-test"))]
pub const ENDPOINT_RECEIVE_FAILED: &str = OPERATION_FAILED;
/// Silent production twins: fail-closed stderr is exactly the generic line.
#[cfg(not(feature = "local-native-enrollment-test"))]
pub const SESSION_OBSERVE_FAILED: &str = OPERATION_FAILED;

#[test]
fn stage_expectations_bind_only_audited_markers_ending_with_generic_error() {
    for expectation in [ENDPOINT_RECEIVE_FAILED, SESSION_OBSERVE_FAILED] {
        let markers = expectation
            .strip_suffix(OPERATION_FAILED)
            .expect("expectation ends with the exact generic final error");
        for line in markers.lines() {
            assert!(
                AUDITED_MARKERS.contains(&line),
                "expectation retained non-audited line {line:?}"
            );
        }
    }
}

#[test]
fn closed_assertion_rejects_arbitrary_leading_stderr() {
    let arbitrary = format!("arbitrary-diagnostic\n{OPERATION_FAILED}");
    assert_closed_rejects(&closed_output_with_stderr(&arbitrary), OPERATION_FAILED);
}

#[test]
fn closed_assertion_rejects_arbitrary_trailing_stderr() {
    let arbitrary = format!("{OPERATION_FAILED}arbitrary-trailing\n");
    assert_closed_rejects(&closed_output_with_stderr(&arbitrary), OPERATION_FAILED);
}

#[test]
fn closed_assertion_rejects_unexpected_stage_marker_in_sequence() {
    let arbitrary = format!("writer-stage=authenticated-run\n{ENDPOINT_RECEIVE_FAILED}");
    assert_closed_rejects(
        &closed_output_with_stderr(&arbitrary),
        ENDPOINT_RECEIVE_FAILED,
    );
}

#[test]
fn closed_assertion_rejects_nonempty_stdout() {
    let mut output = closed_output_with_stderr(OPERATION_FAILED);
    output.stdout = b"arbitrary-stdout\n".to_vec();
    assert_closed_rejects(&output, OPERATION_FAILED);
}

#[test]
fn closed_assertion_rejects_wrong_exit_code() {
    let mut output = closed_output_with_stderr(OPERATION_FAILED);
    output.status = ExitStatus::from_raw(0);
    assert_closed_rejects(&output, OPERATION_FAILED);
}

fn closed_output_with_stderr(stderr: &str) -> Output {
    Output {
        status: ExitStatus::from_raw(4 << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

fn assert_closed_rejects(output: &Output, expected: &str) {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_closed(output, expected);
    }))
    .expect_err("fail-closed assertion must reject this output");
}

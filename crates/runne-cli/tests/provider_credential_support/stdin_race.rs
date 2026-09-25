//! Deterministic regression coverage for the harness stdin write race.
//!
//! `set`/`delete` children reject with `UnsupportedCredentialBackend` before
//! reading stdin, so a child that exits while the parent is still writing
//! the piped input closes the pipe and the parent write reports
//! `BrokenPipe`. The write policy here admits `BrokenPipe` only for
//! scenarios whose child is expected to leave stdin unread; for scenarios
//! that must consume the input every write failure stays fatal.

use std::io::{ErrorKind, Write as _};
use std::process::{Child, ChildStdin};

use crate::provider_credential_cases::{CHILD_CASES, ChildCase, StdinExpectation};

#[derive(Debug, PartialEq)]
enum StdinWrite {
    Delivered,
    ClosedByChild,
}

fn deliver_stdin(stdin: &mut ChildStdin, input: &[u8]) -> StdinWrite {
    match stdin.write_all(input) {
        Ok(()) => StdinWrite::Delivered,
        Err(error) if error.kind() == ErrorKind::BrokenPipe => StdinWrite::ClosedByChild,
        Err(error) => panic!("write stdin: {error}"),
    }
}

fn deliver_or_panic(stdin: &mut ChildStdin, input: &[u8], expectation: StdinExpectation) {
    if deliver_stdin(stdin, input) == StdinWrite::ClosedByChild
        && expectation == StdinExpectation::MustReachChild
    {
        panic!("write stdin: child closed stdin before consuming required input");
    }
}

pub fn write_child_stdin(child: &mut Child, input: &[u8], expectation: StdinExpectation) {
    deliver_or_panic(&mut child.stdin.take().expect("stdin"), input, expectation);
}

fn set_case() -> &'static ChildCase {
    CHILD_CASES
        .iter()
        .find(|candidate| candidate.scenario == "set")
        .expect("set scenario present in CHILD_CASES")
}

/// The historical race made deterministic: the child is fully reaped before
/// the parent writes, so the non-empty input can only meet a closed pipe.
pub fn early_stdin_close_reproducer() {
    let case = set_case();
    let mut child = crate::spawn_child(case.scenario, case.command, case.input, case.terminal);
    let mut stdin = child.stdin.take().expect("stdin");
    let output = child.wait_with_output().expect("wait harness child");
    assert_eq!(
        deliver_stdin(&mut stdin, case.input),
        StdinWrite::ClosedByChild,
        "reaped child must close the stdin pipe before the write"
    );
    deliver_or_panic(&mut stdin, case.input, case.stdin);
    // A tolerated BrokenPipe must not weaken any child outcome assertion.
    assert_eq!(
        output.status.code(),
        Some(case.expected_code),
        "{}",
        case.scenario
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        case.expected_stdout,
        "{}",
        case.scenario
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("process-secret-marker"),
        "{}",
        case.scenario
    );
    assert_eq!(
        stderr,
        crate::expected_stderr(case.scenario, case.expected_code),
        "{}",
        case.scenario
    );
}

/// `BrokenPipe` must never be blanket-ignored: when a scenario requires the
/// input to reach the child, the same write must stay fatal.
pub fn unconsumed_stdin_write_stays_fatal() {
    let case = set_case();
    let mut child = crate::spawn_child(case.scenario, case.command, case.input, case.terminal);
    let mut stdin = child.stdin.take().expect("stdin");
    child.wait_with_output().expect("wait harness child");
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        deliver_or_panic(&mut stdin, case.input, StdinExpectation::MustReachChild);
    }));
    std::panic::set_hook(previous_hook);
    assert!(
        result.is_err(),
        "BrokenPipe write must stay fatal for consumed-input scenarios"
    );
}

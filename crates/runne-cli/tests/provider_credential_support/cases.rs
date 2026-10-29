/// Parent-side expectation for the piped stdin write of a child scenario.
///
/// Determines whether a `BrokenPipe` write failure (the child exited before
/// the harness parent finished writing the piped input) is admissible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdinExpectation {
    /// The child rejects before ever reading stdin, so an early child exit
    /// closing the pipe is benign: the child outcome assertions (exit code,
    /// stdout, stderr) still fully gate the scenario.
    UnusedByChild,
    /// The child must consume the piped input; any stdin write failure,
    /// including `BrokenPipe`, is a harness failure.
    MustReachChild,
}

pub struct ChildCase {
    pub scenario: &'static str,
    pub command: &'static [&'static str],
    pub input: &'static [u8],
    pub stdin: StdinExpectation,
    pub terminal: bool,
    pub expected_stdout: &'static str,
    pub expected_code: i32,
}

const SET_COMMAND: &[&str] = &["provider", "credential", "set", "--provider", "openai"];
const STATUS_COMMAND: &[&str] = &["provider", "credential", "status", "--provider", "openai"];
const DELETE_COMMAND: &[&str] = &["provider", "credential", "delete", "--provider", "openai"];
const LARGE_CREDENTIAL: &[u8; 4_096] = &[b'x'; 4_096];

// Every current scenario rejects before reading stdin: `Set`/`Delete`
// discard their input (`execute_provider_credential_on_platform` returns
// `UnsupportedCredentialBackend` without touching it) and the `Status`
// paths read no input and use an empty one, so all cases declare
// `UnusedByChild`.
pub const CHILD_CASES: &[ChildCase] = &[
    ChildCase {
        scenario: "set",
        command: SET_COMMAND,
        input: b"stdin-secret",
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "status",
        command: STATUS_COMMAND,
        input: b"",
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "configured\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "delete",
        command: DELETE_COMMAND,
        input: b"",
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "exact4096",
        command: SET_COMMAND,
        input: LARGE_CREDENTIAL,
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "tty",
        command: SET_COMMAND,
        input: b"credential",
        stdin: StdinExpectation::UnusedByChild,
        terminal: true,
        expected_stdout: "configured\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "backend-error",
        command: STATUS_COMMAND,
        input: b"",
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "set-resolver-error",
        command: SET_COMMAND,
        input: b"stdin-secret",
        stdin: StdinExpectation::UnusedByChild,
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "set-backend-error",
        command: SET_COMMAND,
        input: b"stdin-secret",
        stdin: StdinExpectation::UnusedByChild,
        terminal: true,
        expected_stdout: "",
        expected_code: 4,
    },
];

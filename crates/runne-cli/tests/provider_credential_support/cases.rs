pub struct ChildCase {
    pub scenario: &'static str,
    pub command: &'static [&'static str],
    pub input: &'static [u8],
    pub terminal: bool,
    pub expected_stdout: &'static str,
    pub expected_code: i32,
}

const SET_COMMAND: &[&str] = &[
    "provider",
    "credential",
    "set",
    "--provider",
    "openai",
    "--stdin",
];
const STATUS_COMMAND: &[&str] = &["provider", "credential", "status", "--provider", "openai"];
const DELETE_COMMAND: &[&str] = &["provider", "credential", "delete", "--provider", "openai"];
const MISSING_STDIN_COMMAND: &[&str] = &["provider", "credential", "set", "--provider", "openai"];
const LARGE_CREDENTIAL: &[u8; 4_096] = &[b'x'; 4_096];

pub const CHILD_CASES: &[ChildCase] = &[
    ChildCase {
        scenario: "set",
        command: SET_COMMAND,
        input: b"stdin-secret",
        terminal: false,
        expected_stdout: "configured\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "status",
        command: STATUS_COMMAND,
        input: b"",
        terminal: false,
        expected_stdout: "configured\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "delete",
        command: DELETE_COMMAND,
        input: b"",
        terminal: false,
        expected_stdout: "missing\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "exact4096",
        command: SET_COMMAND,
        input: LARGE_CREDENTIAL,
        terminal: false,
        expected_stdout: "configured\n",
        expected_code: 0,
    },
    ChildCase {
        scenario: "tty",
        command: SET_COMMAND,
        input: b"credential",
        terminal: true,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "backend-error",
        command: STATUS_COMMAND,
        input: b"",
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "set-resolver-error",
        command: SET_COMMAND,
        input: b"stdin-secret",
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "set-backend-error",
        command: SET_COMMAND,
        input: b"stdin-secret",
        terminal: false,
        expected_stdout: "",
        expected_code: 4,
    },
    ChildCase {
        scenario: "missing-stdin",
        command: MISSING_STDIN_COMMAND,
        input: b"",
        terminal: false,
        expected_stdout: "",
        expected_code: 2,
    },
];

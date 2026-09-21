// Help texts and version for the CLI.

/// Top-level help text.
pub const TOP_LEVEL_HELP: &str = "\
Runne command-line interface.

Usage:
  runne [options] <command> [<args>]
  runne help [<command>]
  runne authority --help
  runne release --help

Options:
  -h, --help       Show this help message
  -V, --version    Show version information

Commands:
  conversation     Manage conversations
  task             Inspect runtime task runs (read-only)
  provider         Manage provider credentials
  status           Show runtime connection status
  health           Check runtime health status
  doctor           Run comprehensive system diagnostics
  completion       Generate shell completion scripts
  authority        Manage project-owner authority
  release          Manage release authority

Run 'runne help <command>' for more information on a command.";

/// Help text for the `conversation` command.
pub const CONVERSATION_HELP: &str = "\
Manage conversations.

Usage:
  runne conversation <subcommand> [<args>]

Subcommands:
  create     Create a new conversation
  send       Send a message and receive a response
  messages   List messages in a conversation

Global options:
  --profile PATH   Path to local runtime profile

Run 'runne help conversation <subcommand>' for more information.";

/// Help text for `conversation create`.
pub const CONVERSATION_CREATE_HELP: &str = "\
Create a new conversation.

Usage:
  runne [--profile PATH] conversation create --workspace-id UUID

Options:
  --workspace-id UUID   Workspace identifier (required)

Examples:
  runne conversation create --workspace-id 018f2e3a-7000-7000-8000-000000000001";

/// Help text for `conversation send`.
pub const CONVERSATION_SEND_HELP: &str = "\
Send a message and receive a response.

Usage:
  runne [--profile PATH] conversation send --conversation-id UUID --expected-version N --text TEXT

Options:
  --conversation-id UUID    Target conversation identifier (required)
  --expected-version N      Expected stream version (required)
  --text TEXT               Message text (required)

Examples:
  runne conversation send --conversation-id 018f2e3a-7000-7000-8000-000000000001 \\
    --expected-version 1 --text \"Hello\"";

/// Help text for `conversation messages`.
pub const CONVERSATION_MESSAGES_HELP: &str = "\
List messages in a conversation.

Usage:
  runne [--profile PATH] conversation messages --conversation-id UUID

Options:
  --conversation-id UUID    Target conversation identifier (required)

Examples:
  runne conversation messages --conversation-id 018f2e3a-7000-7000-8000-000000000001";

/// Help text for the `provider` command.
pub const PROVIDER_HELP: &str = "\
Manage provider credentials.

Usage:
  runne provider <subcommand> [<args>]

Subcommands:
  credential   Manage provider credentials

Run 'runne help provider <subcommand>' for more information.";

/// Help text for `provider credential`.
pub const PROVIDER_CREDENTIAL_HELP: &str = "\
Manage provider credentials.

Usage:
  runne provider credential <subcommand> [<args>]

Subcommands:
  status   Check credential status

Legacy commands:
  set      Unavailable direct credential enrollment
  delete   Unavailable direct credential deletion

Run 'runne help provider credential <subcommand>' for more information.";

/// Help text for `provider credential set`.
pub const PROVIDER_CREDENTIAL_SET_HELP: &str = "\
Direct provider credential enrollment is unavailable.

The legacy stdin command is retained only for compatibility and always
returns an unsupported credential-backend error. Credential material is
not read from standard input.";

/// Help text for `provider credential status`.
pub const PROVIDER_CREDENTIAL_STATUS_HELP: &str = "\
Check credential status.

Usage:
  runne provider credential status --provider openai
  runne provider credential status --provider deepseek

Options:
  --provider <provider>   Provider name: openai or deepseek

Output:
  configured    Credential is stored
  missing       No credential is stored
  unsupported   Credential backend is not available

Examples:
  runne provider credential status --provider openai
  runne provider credential status --provider deepseek";

/// Help text for `provider credential delete`.
pub const PROVIDER_CREDENTIAL_DELETE_HELP: &str = "\
Direct provider credential deletion is unavailable.

The legacy command is retained only for compatibility and always returns
an unsupported credential-backend error.";

/// Help text for the `status` command.
pub const STATUS_HELP: &str = "\
Show runtime connection status.

Usage:
  runne [--profile PATH] status

Options:
  --profile PATH   Path to local runtime profile

This command verifies the local runtime profile and attempts to connect
to the runtime daemon. It reports the connection status, principal,
generation, the active provider selection, and the active provider's
credential status. No credential material is printed.

Examples:
  runne status
  runne --profile /path/to/profile.json status";

/// Returns help text for a command path.
#[must_use]
pub fn help_for(command_path: &[&str]) -> &'static str {
    match command_path {
        ["conversation"] => CONVERSATION_HELP,
        ["conversation", "create"] => CONVERSATION_CREATE_HELP,
        ["conversation", "send"] => CONVERSATION_SEND_HELP,
        ["conversation", "messages"] => CONVERSATION_MESSAGES_HELP,
        ["task"] => TASK_HELP,
        ["task", "list"] => TASK_LIST_HELP,
        ["task", "get"] => TASK_GET_HELP,
        ["provider"] => PROVIDER_HELP,
        ["provider", "credential"] => PROVIDER_CREDENTIAL_HELP,
        ["provider", "credential", "set"] => PROVIDER_CREDENTIAL_SET_HELP,
        ["provider", "credential", "status"] => PROVIDER_CREDENTIAL_STATUS_HELP,
        ["provider", "credential", "delete"] => PROVIDER_CREDENTIAL_DELETE_HELP,
        ["status"] => STATUS_HELP,
        ["health"] => HEALTH_HELP,
        ["doctor"] => DOCTOR_HELP,
        ["completion"] => COMPLETION_HELP,
        ["authority"] => AUTHORITY_HELP,
        ["release"] => RELEASE_HELP,
        _ => TOP_LEVEL_HELP,
    }
}

/// Version string.
#[must_use]
pub fn version_string() -> String {
    format!("runne {}", env!("CARGO_PKG_VERSION"))
}

/// Legacy usage text (alias for top-level help).
pub const USAGE: &str = TOP_LEVEL_HELP;

/// Help text for the `authority` command.
pub const AUTHORITY_HELP: &str =
    "Manage project-owner authority.\n\nUsage:\n  runne authority --help";

/// Help text for the `release` command.
pub const RELEASE_HELP: &str = "Manage release authority.\n\nUsage:\n  runne release --help";

/// Help text for the `health` command.
pub const HEALTH_HELP: &str = "\
Check runtime health status.

Usage:
  runne [--profile PATH] health

Options:
  --profile PATH   Path to local runtime profile

This command performs a quick health check against the runtime daemon.
It returns the runtime status (ok, degraded, unavailable, shutting_down)
and version information.

Exit codes:
  0  Runtime is healthy (status: ok)
  1  Runtime is unhealthy or connection failed
  3  Profile error

Examples:
  runne health
  runne --profile /path/to/profile.json health";

/// Help text for the `doctor` command.
pub const DOCTOR_HELP: &str = "\
Run comprehensive system diagnostics.

Usage:
  runne doctor

This command performs a complete health check of the Runne CLI system:
  - Profile: Checks if the runtime profile exists and is valid
  - Runtime: Verifies connectivity and health status
  - Active provider: Reports the exact provider selection
    (deterministic mode or live provider with model/profile)
  - Credentials: Checks per-provider credential status (openai, deepseek)

No credential material is printed. Diagnostics work without a stored
credential; provider execution fails closed separately.

Exit codes:
  0  All checks passed
  1  Some checks failed
  3  Profile error

Examples:
  runne doctor";

/// Help text for the `completion` command.
pub const COMPLETION_HELP: &str = "\
Generate shell completion scripts.

Usage:
  runne completion <shell>

Supported shells:
  bash         Generate Bash completion script
  zsh          Generate Zsh completion script
  fish         Generate Fish completion script
  powershell   Generate PowerShell completion script

Examples:
  runne completion bash > ~/.bash_completion.d/runne
  runne completion zsh > ~/.zsh/completion/_runne
  runne completion fish > ~/.config/fish/completions/runne.fish
  runne completion powershell > $PROFILE";

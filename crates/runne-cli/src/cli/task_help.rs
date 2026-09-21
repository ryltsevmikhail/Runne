// Help texts for the read-only `task` command; kept as a separate include!
// part so test harness scopes that mirror `help.rs` can share them.

/// Help text for the `task` command.
pub const TASK_HELP: &str = "\
Inspect runtime task runs (read-only).

Usage:
  runne [--profile PATH] task <subcommand> [<args>]

Subcommands:
  list   List all runtime task runs
  get    Read a single task run snapshot

Global options:
  --profile PATH   Path to local runtime profile (must precede the command)

Run 'runne help task <subcommand>' for more information.";

/// Help text for `task list`.
pub const TASK_LIST_HELP: &str = "\
List runtime task runs.

Usage:
  runne [--profile PATH] task list

The public runtime API returns the full task run list (bounded internally
at 4096 items); pagination flags (limit/offset/cursor) do not exist and
any extra argument is rejected as a usage error.

Examples:
  runne task list
  runne --profile /path/to/profile.json task list
  runne --format json task list";

/// Help text for `task get`.
pub const TASK_GET_HELP: &str = "\
Read a single runtime task run snapshot.

Usage:
  runne [--profile PATH] task get --task-run-id UUID

Options:
  --task-run-id UUID   Task run identifier (required, RFC 9562 UUIDv7)

Examples:
  runne task get --task-run-id 018f2e3a-7000-7000-8000-000000000001
  runne --format json task get --task-run-id 018f2e3a-7000-7000-8000-000000000001";

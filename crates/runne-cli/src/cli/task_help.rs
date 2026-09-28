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

/// Help text for the headless `exec` command.
pub const EXEC_HELP: &str = "\
Submit one headless task run and stream its lifecycle events.

Usage:
  runne [--profile PATH] exec --conversation-id UUID --workspace-id UUID [--prompt TEXT]

Options:
  --conversation-id UUID   Target conversation identifier (required)
  --workspace-id UUID      Owning workspace identifier (required)
  --prompt TEXT            Prompt text; when omitted, the prompt is read from
                           piped stdin (non-TTY headless path)
  --model MODEL            Request the exact provider model; admission
                           compares it against the runtime-pinned model and
                           rejects a mismatch (error code `model_mismatch`)
                           before any effect

The command exits 0 only on a `succeeded` terminal outcome. Other terminal
outcomes print the full event stream to stdout and exit non-zero. If the
bounded wait expires without a terminal outcome, the run stays uncertain
(error code `task_uncertain`, exit 5).

Examples:
  runne exec --conversation-id 018f2e3a-7000-7000-8000-000000000001 \\
    --workspace-id 018f2e3a-7000-7000-8000-000000000002 --prompt \"Fix the test\"
  echo \"Fix the test\" | runne --format jsonl exec \\
    --conversation-id 018f2e3a-7000-7000-8000-000000000001 \\
    --workspace-id 018f2e3a-7000-7000-8000-000000000002";

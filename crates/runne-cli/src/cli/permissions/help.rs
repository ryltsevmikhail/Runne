const PERMISSIONS_HELP: &str = "\
Read runtime-owned permission mode and approval projections.

Usage:
  runne [--profile PATH] permissions <subcommand> [<args>]

Protected runtime:
  runne permissions --protected-runtime-root PATH [--project-root PATH] <subcommand>
  --project-root PATH  rebind the root of an already open and trusted project
                       workspace so the current daemon can observe it; consumed
                       admission nonce

Subcommands:
  status             Read the selected and effective mode separately
  command status     Read a permission-mode command outcome
  mode set           Request a V2 mode change with durable local recovery
  approvals list     List pending approvals
  approvals respond  Confirm and submit one approval decision

Approval responses require a caller-supplied command ID and idempotency key.
Each response displays the exact request in a native Linux confirmation dialog.";

const PERMISSIONS_STATUS_HELP: &str = "\
Read the current selected and effective permission mode.

Usage:
  runne [--profile PATH] permissions status --workspace-id UUID

Options:
  --workspace-id UUID   Workspace identifier (required)

Selected mode is a stored selection. Effective state is reported separately;
a selected full-access mode does not imply that native enforcement is ready.";

const PERMISSIONS_COMMAND_STATUS_HELP: &str = "\
Read back one permission-mode command without resending it.

Usage:
  runne [--profile PATH] permissions command status --workspace-id UUID --command-id UUID

Options:
  --workspace-id UUID   Workspace identifier (required)
  --command-id UUID     Previously issued command identifier (required)

Pending native confirmation is reported as a required native action. A
committed receipt does not replace a fresh effective-mode status read.";

const PERMISSIONS_APPROVALS_LIST_HELP: &str = "\
List approvals visible to the authenticated runtime profile.

Usage:
  runne [--profile PATH] permissions approvals list

This command is read-only. It does not approve or deny any request.";

const PERMISSIONS_APPROVALS_HELP: &str = "\
Read or respond to approvals visible to the authenticated runtime profile.

Subcommands:
  list      List pending and terminal approvals
  respond   Confirm and submit one decision through a native dialog";

const PERMISSIONS_APPROVALS_RESPOND_HELP: &str = "\
Submit one approval decision after exact native confirmation.

Usage:
  runne [--profile PATH] permissions approvals respond --approval-id UUID \\
--decision approve|deny --command-id UUID --idempotency-key KEY

Options:
  --approval-id UUID       Target approval (required)
  --decision VALUE         approve or deny (required)
  --command-id UUID        Caller-supplied command UUIDv7 (required)
  --idempotency-key KEY    Caller-supplied idempotency key (required)

The command reads the canonical approval, shows its exact disclosure in a
native Linux dialog, rechecks it, records the witness, then submits once.
Retries and restart recovery read the command reconciliation endpoint only.";

const PERMISSIONS_MODE_SET_HELP: &str = "\
Request one permission-mode change through the authenticated V2 runtime client.

Usage:
  runne [--profile PATH] permissions mode set --workspace-id UUID --command-id UUID \
--idempotency-key KEY --mode MODE --expected-revision N --preset-version 1 \
--expires-at-unix-ms none|N

Options:
  --workspace-id UUID       Target workspace UUIDv7 (required)
  --command-id UUID         Caller-supplied command UUIDv7 (required)
  --idempotency-key KEY     Caller-supplied key (required)
  --mode MODE               ask_always, risk_based, or full_access
  --expected-revision N     Observed authorization revision
  --preset-version 1        Frozen V2 preset version
  --expires-at-unix-ms VAL  none or a positive Unix-millisecond deadline

The command records its exact intent before the single POST. A later invocation
with that identity performs readback only; it never resends the request.
Effective readiness is reported only by a separate current status read.
Native authentication and approval decisions stay in their trusted hosts.";

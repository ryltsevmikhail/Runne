r"
# Fish completion for runne
# Add to ~/.config/fish/completions/runne.fish:
#   runne completion fish > ~/.config/fish/completions/runne.fish
# Disable file completions by default
complete -c runne -f

# Top-level commands
complete -c runne -n __fish_use_subcommand -a conversation -d 'Manage conversations'
complete -c runne -n __fish_use_subcommand -a task -d 'Inspect runtime task runs'
complete -c runne -n __fish_use_subcommand -a provider -d 'Manage provider credentials'
complete -c runne -n __fish_use_subcommand -a permissions -d 'Read modes and pending approvals'
complete -c runne -n __fish_use_subcommand -a status -d 'Show runtime connection status'
complete -c runne -n __fish_use_subcommand -a health -d 'Check runtime health status'
complete -c runne -n __fish_use_subcommand -a doctor -d 'Run comprehensive system diagnostics'
complete -c runne -n __fish_use_subcommand -a completion -d 'Generate shell completion scripts'
complete -c runne -n __fish_use_subcommand -a authority -d 'Manage project-owner authority'
complete -c runne -n __fish_use_subcommand -a release -d 'Manage release authority'
complete -c runne -n __fish_use_subcommand -a help -d 'Show help information'

# Global options
complete -c runne -l help -d 'Show help information'
complete -c runne -l version -d 'Show version information'
complete -c runne -l format -xa 'text json' -d 'Output format'
complete -c runne -l profile -rF -d 'Path to runtime profile'

# Conversation subcommands
complete -c runne -n '__fish_seen_subcommand_from conversation' -a create -d 'Create a new conversation'
complete -c runne -n '__fish_seen_subcommand_from conversation' -a send -d 'Send a message'
complete -c runne -n '__fish_seen_subcommand_from conversation' -a messages -d 'List messages'
complete -c runne -n '__fish_seen_subcommand_from conversation' -l help -d 'Show help'

# Task subcommands
complete -c runne -n '__fish_seen_subcommand_from task' -a list -d 'List task runs'
complete -c runne -n '__fish_seen_subcommand_from task' -a get -d 'Get a task run'
complete -c runne -n '__fish_seen_subcommand_from task' -l help -d 'Show help'
complete -c runne -n '__fish_seen_subcommand_from get' -l task-run-id -r -d 'Task run ID'

# Provider subcommands
complete -c runne -n '__fish_seen_subcommand_from provider' -a credential -d 'Manage credentials'
complete -c runne -n '__fish_seen_subcommand_from provider' -l help -d 'Show help'

# Read-only permission projections
complete -c runne -n '__fish_seen_subcommand_from permissions' -a 'status command mode approvals' -d 'Permission query or mode change'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from command' -a status -d 'Read command outcome'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from approvals' -a 'list respond' -d 'List or respond to approvals'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from mode' -a set -d 'Request a mode change'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from status' -l workspace-id -r -d 'Workspace ID'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from status' -l help -d 'Show help'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from command' -l workspace-id -r -d 'Workspace ID'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from command' -l command-id -r -d 'Permission command ID'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l workspace-id -r -d 'Workspace ID'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l command-id -r -d 'Caller-supplied command UUIDv7'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l idempotency-key -r -d 'Caller-supplied idempotency key'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l mode -xa 'ask_always risk_based full_access' -d 'Requested mode'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l expected-revision -r -d 'Observed authorization revision'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l preset-version -xa 1 -d 'Preset version'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from set' -l expires-at-unix-ms -xa none -d 'none or positive deadline'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from respond' -l approval-id -r -d 'Approval ID'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from respond' -l decision -xa 'approve deny' -d 'Decision to confirm'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from respond' -l command-id -r -d 'Caller-supplied command UUIDv7'
complete -c runne -n '__fish_seen_subcommand_from permissions; and __fish_seen_subcommand_from respond' -l idempotency-key -r -d 'Caller-supplied idempotency key'

# Credential subcommands
complete -c runne -n '__fish_seen_subcommand_from credential' -a status -d 'Check status'
complete -c runne -n '__fish_seen_subcommand_from credential' -l help -d 'Show help'
complete -c runne -n '__fish_seen_subcommand_from credential' -l provider -xa 'openai deepseek' -d 'Provider name'

# Completion subcommands
complete -c runne -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell' -d 'Shell type'

# Conversation options
complete -c runne -n '__fish_seen_subcommand_from create' -l workspace-id -r -d 'Workspace ID'
complete -c runne -n '__fish_seen_subcommand_from send' -l conversation-id -r -d 'Conversation ID'
complete -c runne -n '__fish_seen_subcommand_from send' -l expected-version -r -d 'Expected version'
complete -c runne -n '__fish_seen_subcommand_from send' -l text -r -d 'Message text'
complete -c runne -n '__fish_seen_subcommand_from messages' -l conversation-id -r -d 'Conversation ID'
".to_string()

pub(super) fn generate() -> String {
    r"
# Fish completion for runne
# Add to ~/.config/fish/completions/runne.fish:
#   runne completion fish > ~/.config/fish/completions/runne.fish

# Disable file completions by default
complete -c runne -f

# Top-level commands
complete -c runne -n __fish_use_subcommand -a conversation -d 'Manage conversations'
complete -c runne -n __fish_use_subcommand -a provider -d 'Manage provider credentials'
complete -c runne -n __fish_use_subcommand -a status -d 'Show runtime connection status'
complete -c runne -n __fish_use_subcommand -a health -d 'Check runtime health status'
complete -c runne -n __fish_use_subcommand -a doctor -d 'Run comprehensive system diagnostics'
complete -c runne -n __fish_use_subcommand -a completion -d 'Generate shell completion scripts'
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

# Provider subcommands
complete -c runne -n '__fish_seen_subcommand_from provider' -a credential -d 'Manage credentials'
complete -c runne -n '__fish_seen_subcommand_from provider' -l help -d 'Show help'

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
}

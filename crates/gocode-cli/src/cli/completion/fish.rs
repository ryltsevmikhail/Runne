pub(super) fn generate() -> String {
    r"
# Fish completion for gocode
# Add to ~/.config/fish/completions/gocode.fish:
#   gocode completion fish > ~/.config/fish/completions/gocode.fish

# Disable file completions by default
complete -c gocode -f

# Top-level commands
complete -c gocode -n __fish_use_subcommand -a conversation -d 'Manage conversations'
complete -c gocode -n __fish_use_subcommand -a provider -d 'Manage provider credentials'
complete -c gocode -n __fish_use_subcommand -a status -d 'Show runtime connection status'
complete -c gocode -n __fish_use_subcommand -a health -d 'Check runtime health status'
complete -c gocode -n __fish_use_subcommand -a doctor -d 'Run comprehensive system diagnostics'
complete -c gocode -n __fish_use_subcommand -a completion -d 'Generate shell completion scripts'
complete -c gocode -n __fish_use_subcommand -a help -d 'Show help information'

# Global options
complete -c gocode -l help -d 'Show help information'
complete -c gocode -l version -d 'Show version information'
complete -c gocode -l format -xa 'text json' -d 'Output format'
complete -c gocode -l profile -rF -d 'Path to runtime profile'

# Conversation subcommands
complete -c gocode -n '__fish_seen_subcommand_from conversation' -a create -d 'Create a new conversation'
complete -c gocode -n '__fish_seen_subcommand_from conversation' -a send -d 'Send a message'
complete -c gocode -n '__fish_seen_subcommand_from conversation' -a messages -d 'List messages'
complete -c gocode -n '__fish_seen_subcommand_from conversation' -l help -d 'Show help'

# Provider subcommands
complete -c gocode -n '__fish_seen_subcommand_from provider' -a credential -d 'Manage credentials'
complete -c gocode -n '__fish_seen_subcommand_from provider' -l help -d 'Show help'

# Credential subcommands
complete -c gocode -n '__fish_seen_subcommand_from credential' -a set -d 'Store credential'
complete -c gocode -n '__fish_seen_subcommand_from credential' -a status -d 'Check status'
complete -c gocode -n '__fish_seen_subcommand_from credential' -a delete -d 'Delete credential'
complete -c gocode -n '__fish_seen_subcommand_from credential' -l help -d 'Show help'
complete -c gocode -n '__fish_seen_subcommand_from credential' -l provider -xa 'openai' -d 'Provider name'
complete -c gocode -n '__fish_seen_subcommand_from credential' -l stdin -d 'Read from stdin'

# Completion subcommands
complete -c gocode -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell' -d 'Shell type'

# Conversation options
complete -c gocode -n '__fish_seen_subcommand_from create' -l workspace-id -r -d 'Workspace ID'
complete -c gocode -n '__fish_seen_subcommand_from send' -l conversation-id -r -d 'Conversation ID'
complete -c gocode -n '__fish_seen_subcommand_from send' -l expected-version -r -d 'Expected version'
complete -c gocode -n '__fish_seen_subcommand_from send' -l text -r -d 'Message text'
complete -c gocode -n '__fish_seen_subcommand_from messages' -l conversation-id -r -d 'Conversation ID'
".to_string()
}

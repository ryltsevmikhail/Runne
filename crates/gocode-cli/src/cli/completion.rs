// Shell completion script generation

/// Supported shell types for completion generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

impl Shell {
    /// Parse shell name from string
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "powershell" | "pwsh" => Some(Self::PowerShell),
            _ => None,
        }
    }

    /// Get shell name as string
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
        }
    }
}

/// Generate completion script for the specified shell
#[must_use]
pub fn generate_completion(shell: Shell) -> String {
    match shell {
        Shell::Bash => generate_bash_completion(),
        Shell::Zsh => generate_zsh_completion(),
        Shell::Fish => generate_fish_completion(),
        Shell::PowerShell => generate_powershell_completion(),
    }
}

#[allow(clippy::needless_raw_string_hashes)]
fn generate_bash_completion() -> String {
    r#"
# Bash completion for gocode
# Add to ~/.bashrc or ~/.bash_completion:
#   eval "$(gocode completion bash)"

_gocode() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Top-level commands
    opts="conversation provider status health doctor completion help --help --version --format"
    
    case "${prev}" in
        gocode)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        conversation)
            COMPREPLY=( $(compgen -W "create send messages --help" -- ${cur}) )
            return 0
            ;;
        provider)
            COMPREPLY=( $(compgen -W "credential --help" -- ${cur}) )
            return 0
            ;;
        credential)
            COMPREPLY=( $(compgen -W "set status delete --help" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- ${cur}) )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "text json" -- ${cur}) )
            return 0
            ;;
        --provider)
            COMPREPLY=( $(compgen -W "openai" -- ${cur}) )
            return 0
            ;;
        --conversation-id|--workspace-id)
            # Could integrate with runtime to list actual IDs
            return 0
            ;;
        *)
            ;;
    esac
    
    # Handle flags
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --format --profile" -- ${cur}) )
        return 0
    fi
}

complete -F _gocode gocode
"#.to_string()
}

#[allow(clippy::needless_raw_string_hashes)]
fn generate_zsh_completion() -> String {
    r#"
# Zsh completion for gocode
# Add to ~/.zshrc:
#   eval "$(gocode completion zsh)"

_gocode() {
    local -a commands
    local -a options
    
    commands=(
        'conversation:Manage conversations'
        'provider:Manage provider credentials'
        'status:Show runtime connection status'
        'health:Check runtime health status'
        'doctor:Run comprehensive system diagnostics'
        'completion:Generate shell completion scripts'
        'help:Show help information'
    )
    
    options=(
        '--help[Show help information]'
        '--version[Show version information]'
        '--format[Output format]:format:(text json)'
        '--profile[Path to runtime profile]:profile:_files'
    )
    
    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'
    
    case $state in
        command)
            _describe -t commands 'gocode commands' commands
            _describe -t options 'gocode options' options
            ;;
        args)
            case $words[1] in
                conversation)
                    _arguments \
                        '1:subcommand:((create:"Create a new conversation" send:"Send a message" messages:"List messages"))' \
                        '--help[Show help]' \
                        '--conversation-id[Conversation ID]:id:' \
                        '--workspace-id[Workspace ID]:id:' \
                        '--expected-version[Expected version]:version:' \
                        '--text[Message text]:text:'
                    ;;
                provider)
                    _arguments \
                        '1:subcommand:((credential:"Manage credentials"))' \
                        '--help[Show help]'
                    ;;
                credential)
                    _arguments \
                        '1:subcommand:((set:"Store credential" status:"Check status" delete:"Delete credential"))' \
                        '--help[Show help]' \
                        '--provider[Provider name]:provider:(openai)' \
                        '--stdin[Read from stdin]'
                    ;;
                completion)
                    _arguments \
                        '1:shell:((bash zsh fish powershell))'
                    ;;
                status|health|doctor)
                    _arguments \
                        '--help[Show help]' \
                        '--format[Output format]:format:(text json)'
                    ;;
            esac
            ;;
    esac
}

compdef _gocode gocode
"#.to_string()
}

fn generate_fish_completion() -> String {
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

#[allow(clippy::needless_raw_string_hashes)]
fn generate_powershell_completion() -> String {
    r#"
# PowerShell completion for gocode
# Add to $PROFILE:
#   Invoke-Expression (&gocode completion powershell)

using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'gocode' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    
    $commandElements = $commandAst.CommandElements
    $command = $commandElements[0].Value
    
    # Top-level commands
    $commands = @(
        [CompletionResult]::new('conversation', 'conversation', [CompletionResultType]::ParameterValue, 'Manage conversations')
        [CompletionResult]::new('provider', 'provider', [CompletionResultType]::ParameterValue, 'Manage provider credentials')
        [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show runtime connection status')
        [CompletionResult]::new('health', 'health', [CompletionResultType]::ParameterValue, 'Check runtime health status')
        [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run comprehensive system diagnostics')
        [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate shell completion scripts')
        [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Show help information')
    )
    
    # Global options
    $options = @(
        [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help information')
        [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Show version information')
        [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
        [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Path to runtime profile')
    )
    
    if ($commandElements.Count -eq 1) {
        return $commands + $options
    }
    
    $subcommand = $commandElements[1].Value
    
    switch ($subcommand) {
        'conversation' {
            return @(
                [CompletionResult]::new('create', 'create', [CompletionResultType]::ParameterValue, 'Create a new conversation')
                [CompletionResult]::new('send', 'send', [CompletionResultType]::ParameterValue, 'Send a message')
                [CompletionResult]::new('messages', 'messages', [CompletionResultType]::ParameterValue, 'List messages')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'provider' {
            return @(
                [CompletionResult]::new('credential', 'credential', [CompletionResultType]::ParameterValue, 'Manage credentials')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'credential' {
            return @(
                [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Store credential')
                [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Check status')
                [CompletionResult]::new('delete', 'delete', [CompletionResultType]::ParameterValue, 'Delete credential')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
                [CompletionResult]::new('--provider', '--provider', [CompletionResultType]::ParameterName, 'Provider name')
                [CompletionResult]::new('--stdin', '--stdin', [CompletionResultType]::ParameterName, 'Read from stdin')
            )
        }
        'completion' {
            return @(
                [CompletionResult]::new('bash', 'bash', [CompletionResultType]::ParameterValue, 'Bash shell')
                [CompletionResult]::new('zsh', 'zsh', [CompletionResultType]::ParameterValue, 'Zsh shell')
                [CompletionResult]::new('fish', 'fish', [CompletionResultType]::ParameterValue, 'Fish shell')
                [CompletionResult]::new('powershell', 'powershell', [CompletionResultType]::ParameterValue, 'PowerShell')
            )
        }
        'status' {
            return @(
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
                [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            )
        }
        'health' {
            return @(
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
                [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            )
        }
        'doctor' {
            return @(
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
                [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
            )
        }
    }
    
    return @()
}
"#.to_string()
}

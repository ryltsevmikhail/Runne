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
# Bash completion for runne
# Add to ~/.bashrc or ~/.bash_completion:
#   eval "$(runne completion bash)"

_runne() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Top-level commands
    opts="conversation task provider permissions status health doctor completion authority release help --help --version --format"

    case "${prev}" in
        runne)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        conversation)
            COMPREPLY=( $(compgen -W "create send messages --help" -- ${cur}) )
            return 0
            ;;
        task)
            COMPREPLY=( $(compgen -W "list get --help" -- ${cur}) )
            return 0
            ;;
        provider)
            COMPREPLY=( $(compgen -W "credential --help" -- ${cur}) )
            return 0
            ;;
        permissions)
            COMPREPLY=( $(compgen -W "status command mode approvals --help" -- ${cur}) )
            return 0
            ;;
        mode)
            COMPREPLY=( $(compgen -W "set --help" -- ${cur}) )
            return 0
            ;;
        command)
            COMPREPLY=( $(compgen -W "status" -- ${cur}) )
            return 0
            ;;
        approvals)
            COMPREPLY=( $(compgen -W "list respond" -- ${cur}) )
            return 0
            ;;
        respond)
            COMPREPLY=( $(compgen -W "--approval-id --decision --command-id --idempotency-key --help" -- ${cur}) )
            return 0
            ;;
        --decision)
            COMPREPLY=( $(compgen -W "approve deny" -- ${cur}) )
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
            COMPREPLY=( $(compgen -W "openai deepseek" -- ${cur}) )
            return 0
            ;;
        --conversation-id|--workspace-id|--task-run-id)
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

complete -F _runne runne
"#.to_string()
}

#[allow(clippy::needless_raw_string_hashes)]
fn generate_zsh_completion() -> String {
    r#"
# Zsh completion for runne
# Add to ~/.zshrc:
#   eval "$(runne completion zsh)"

_runne() {
    local -a commands
    local -a options

    commands=(
        'conversation:Manage conversations'
        'task:Inspect runtime task runs (read-only)'
        'provider:Manage provider credentials'
        'permissions:Read selected/effective modes and pending approvals'
        'status:Show runtime connection status'
        'health:Check runtime health status'
        'doctor:Run comprehensive system diagnostics'
        'completion:Generate shell completion scripts'
        'authority:Manage project-owner authority'
        'release:Manage release authority'
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
            _describe -t commands 'runne commands' commands
            _describe -t options 'runne options' options
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
                task)
                    _arguments \
                        '1:subcommand:((list:"List task runs" get:"Get a task run"))' \
                        '--help[Show help]' \
                        '--task-run-id[Task run ID]:id:'
                    ;;
                provider)
                    _arguments \
                        '1:subcommand:((credential:"Manage credentials"))' \
                        '--help[Show help]'
                    ;;
                permissions)
                    _arguments \
                        '1:subcommand:((status:"Read current selected/effective mode" command:"Read command outcome" mode:"Request a mode change" approvals:"List or respond to approvals"))' \
                        '--workspace-id[Workspace ID]:id:' \
                        '--command-id[Command ID]:id:' \
                        '--idempotency-key[Caller-supplied idempotency key]:key:' \
                        '--approval-id[Approval ID]:id:' \
                        '--decision[Decision to confirm]:decision:(approve deny)' \
                        '--mode[Requested mode]:mode:(ask_always risk_based full_access)' \
                        '--expected-revision[Observed authorization revision]:revision:' \
                        '--preset-version[Preset version]:version:(1)' \
                        '--expires-at-unix-ms[none or positive expiry]:expiry:' \
                        '--help[Show help]'
                    ;;
                credential)
                    _arguments \
                        '1:subcommand:((status:"Check status"))' \
                        '--help[Show help]' \
                        '--provider[Provider name]:provider:(openai deepseek)'
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

compdef _runne runne
"#.to_string()
}

fn generate_fish_completion() -> String {
    include!("completion_parts/fish.inc")
}

fn generate_powershell_completion() -> String {
    include!("completion_parts/powershell.inc")
}

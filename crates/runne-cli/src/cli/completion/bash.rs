#[allow(clippy::needless_raw_string_hashes)]
pub(super) fn generate() -> String {
    concat!(
        r#"
# Bash completion for runne
# Add to ~/.bashrc or ~/.bash_completion:
#   eval "$(runne completion bash)"

_runne() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
"#,
        "    ",
        r#"
    # Top-level commands
    opts="conversation provider status health doctor completion help --help --version --format"
"#,
        "    ",
        r#"
    case "${prev}" in
        runne)
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
            COMPREPLY=( $(compgen -W "openai deepseek" -- ${cur}) )
            return 0
            ;;
        --conversation-id|--workspace-id)
            # Could integrate with runtime to list actual IDs
            return 0
            ;;
        *)
            ;;
    esac
"#,
        "    ",
        r#"
    # Handle flags
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --format --profile" -- ${cur}) )
        return 0
    fi
}

complete -F _runne runne
"#,
    )
    .to_string()
}

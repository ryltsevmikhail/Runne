#[allow(clippy::needless_raw_string_hashes)]
pub(super) fn generate() -> String {
    concat!(
        r#"
# Zsh completion for gocode
# Add to ~/.zshrc:
#   eval "$(gocode completion zsh)"

_gocode() {
    local -a commands
    local -a options
"#,
        "    ",
        r#"
    commands=(
        'conversation:Manage conversations'
        'provider:Manage provider credentials'
        'status:Show runtime connection status'
        'health:Check runtime health status'
        'doctor:Run comprehensive system diagnostics'
        'completion:Generate shell completion scripts'
        'help:Show help information'
    )
"#,
        "    ",
        r#"
    options=(
        '--help[Show help information]'
        '--version[Show version information]'
        '--format[Output format]:format:(text json)'
        '--profile[Path to runtime profile]:profile:_files'
    )
"#,
        "    ",
        r#"
    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'
"#,
        "    ",
        r#"
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
"#,
    )
    .to_string()
}

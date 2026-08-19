#[allow(clippy::needless_raw_string_hashes)]
const SCRIPT: &str = concat!(
        r#"
# PowerShell completion for runne
# Add to $PROFILE:
#   Invoke-Expression (&runne completion powershell)

using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'runne' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
"#,
        "    ",
        r#"
    $commandElements = $commandAst.CommandElements
    $command = $commandElements[0].Value
"#,
        "    ",
        r#"
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
"#,
        "    ",
        r#"
    # Global options
    $options = @(
        [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help information')
        [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Show version information')
        [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Output format')
        [CompletionResult]::new('--profile', '--profile', [CompletionResultType]::ParameterName, 'Path to runtime profile')
    )
"#,
        "    ",
        r#"
    if ($commandElements.Count -eq 1) {
        return $commands + $options
    }
"#,
        "    ",
        r#"
    $subcommand = $commandElements[1].Value
"#,
        "    ",
        r#"
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
"#,
        "    ",
        r#"
    return @()
}
"#,
    );

pub(super) fn generate() -> String {
    SCRIPT.to_string()
}

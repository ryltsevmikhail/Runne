r"
# PowerShell completion for runne
# Add to $PROFILE:
#   Invoke-Expression (&runne completion powershell)

using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'runne' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = $commandElements[0].Value

    # Top-level commands
    $commands = @(
        [CompletionResult]::new('conversation', 'conversation', [CompletionResultType]::ParameterValue, 'Manage conversations')
        [CompletionResult]::new('task', 'task', [CompletionResultType]::ParameterValue, 'Inspect runtime task runs')
        [CompletionResult]::new('provider', 'provider', [CompletionResultType]::ParameterValue, 'Manage provider credentials')
        [CompletionResult]::new('permissions', 'permissions', [CompletionResultType]::ParameterValue, 'Read modes and pending approvals')
        [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Show runtime connection status')
        [CompletionResult]::new('health', 'health', [CompletionResultType]::ParameterValue, 'Check runtime health status')
        [CompletionResult]::new('doctor', 'doctor', [CompletionResultType]::ParameterValue, 'Run comprehensive system diagnostics')
        [CompletionResult]::new('completion', 'completion', [CompletionResultType]::ParameterValue, 'Generate shell completion scripts')
        [CompletionResult]::new('authority', 'authority', [CompletionResultType]::ParameterValue, 'Manage project-owner authority')
        [CompletionResult]::new('release', 'release', [CompletionResultType]::ParameterValue, 'Manage release authority')
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
        'task' {
            return @(
                [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List task runs')
                [CompletionResult]::new('get', 'get', [CompletionResultType]::ParameterValue, 'Get a task run')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'provider' {
            return @(
                [CompletionResult]::new('credential', 'credential', [CompletionResultType]::ParameterValue, 'Manage credentials')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'permissions' {
            return @(
                [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Read current selected/effective mode')
                [CompletionResult]::new('command', 'command', [CompletionResultType]::ParameterValue, 'Read permission command outcome')
                [CompletionResult]::new('mode', 'mode', [CompletionResultType]::ParameterValue, 'Request a mode change')
                [CompletionResult]::new('approvals', 'approvals', [CompletionResultType]::ParameterValue, 'List pending approvals')
                [CompletionResult]::new('--workspace-id', '--workspace-id', [CompletionResultType]::ParameterName, 'Workspace ID')
                [CompletionResult]::new('--command-id', '--command-id', [CompletionResultType]::ParameterName, 'Permission command ID')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'command' {
            return @(
                [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Read permission command outcome')
                [CompletionResult]::new('--workspace-id', '--workspace-id', [CompletionResultType]::ParameterName, 'Workspace ID')
                [CompletionResult]::new('--command-id', '--command-id', [CompletionResultType]::ParameterName, 'Permission command ID')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'mode' {
            return @(
                [CompletionResult]::new('set', 'set', [CompletionResultType]::ParameterValue, 'Request one mode change')
                [CompletionResult]::new('--workspace-id', '--workspace-id', [CompletionResultType]::ParameterName, 'Workspace ID')
                [CompletionResult]::new('--command-id', '--command-id', [CompletionResultType]::ParameterName, 'Caller-supplied command UUIDv7')
                [CompletionResult]::new('--idempotency-key', '--idempotency-key', [CompletionResultType]::ParameterName, 'Caller-supplied key')
                [CompletionResult]::new('--mode', '--mode', [CompletionResultType]::ParameterName, 'ask_always, risk_based, or full_access')
                [CompletionResult]::new('--expected-revision', '--expected-revision', [CompletionResultType]::ParameterName, 'Observed authorization revision')
                [CompletionResult]::new('--preset-version', '--preset-version', [CompletionResultType]::ParameterName, 'Preset version 1')
                [CompletionResult]::new('--expires-at-unix-ms', '--expires-at-unix-ms', [CompletionResultType]::ParameterName, 'none or positive deadline')
            )
        }
        'approvals' {
            return @(
                [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List pending approvals')
                [CompletionResult]::new('respond', 'respond', [CompletionResultType]::ParameterValue, 'Confirm and submit one approval decision')
                [CompletionResult]::new('--approval-id', '--approval-id', [CompletionResultType]::ParameterName, 'Approval ID')
                [CompletionResult]::new('--decision', '--decision', [CompletionResultType]::ParameterName, 'approve or deny')
                [CompletionResult]::new('--command-id', '--command-id', [CompletionResultType]::ParameterName, 'Caller-supplied command UUIDv7')
                [CompletionResult]::new('--idempotency-key', '--idempotency-key', [CompletionResultType]::ParameterName, 'Caller-supplied idempotency key')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
            )
        }
        'credential' {
            return @(
                [CompletionResult]::new('status', 'status', [CompletionResultType]::ParameterValue, 'Check status')
                [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Show help')
                [CompletionResult]::new('--provider', '--provider', [CompletionResultType]::ParameterName, 'Provider name')
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
".to_string()

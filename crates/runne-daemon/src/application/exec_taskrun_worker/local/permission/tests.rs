use super::terminal_commit::running_completion;
use runne_domain::command::{TaskRunCommand, TerminalResult};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;

#[test]
fn normal_exit_137_is_not_rewritten_as_a_signal() {
    let (command, result) = running_completion(LinuxLeaderExitKindV1::Exited { code: 137 }, false);
    assert!(matches!(
        command,
        TaskRunCommand::Complete {
            result: TerminalResult::Failure { reason }
        } if reason == "local_command_exit_137"
    ));
    assert_eq!(
        result,
        TerminalResult::Failure {
            reason: "local_command_exit_137".into()
        }
    );
}

#[test]
fn signaled_exit_keeps_the_typed_signal_reason() {
    let (command, result) = running_completion(
        LinuxLeaderExitKindV1::Signaled {
            signal: 9,
            core_dumped: false,
        },
        false,
    );
    assert!(matches!(
        command,
        TaskRunCommand::Fail { reason } if reason == "local_command_signal_v1_9"
    ));
    assert_eq!(
        result,
        TerminalResult::Failure {
            reason: "local_command_signal_v1_9".into()
        }
    );
}

#[test]
fn policy_stop_wins_over_a_successful_exit() {
    let (command, result) = running_completion(LinuxLeaderExitKindV1::Exited { code: 0 }, true);
    assert!(matches!(
        command,
        TaskRunCommand::Fail { reason } if reason == "local_command_policy_stopped_v1"
    ));
    assert_eq!(
        result,
        TerminalResult::Failure {
            reason: "local_command_policy_stopped_v1".into()
        }
    );
}

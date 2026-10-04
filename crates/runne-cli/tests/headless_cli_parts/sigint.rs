//! Bounded-SIGINT scenarios: the real CLI binary execs against a live
//! daemon; the first SIGINT requests durable cancellation, the second exits
//! immediately without a terminal claim.

#![cfg(unix)]

pub mod sigint_scenario {
    use crate::support::{connect_client, seed_conversation, start_test_daemon, stop_daemon};
    use runne_runtime_client::{ReplayAggregateKind, ReplayScope};
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};

    struct Child {
        process: tokio::process::Child,
        stdout_lines: BufReader<tokio::process::ChildStdout>,
        stderr: Option<tokio::process::ChildStderr>,
    }

    fn spawn_exec(profile_arg: &str, conversation_id: &str, workspace_id: &str) -> Child {
        let executable = env!("CARGO_BIN_EXE_runne");
        let mut child = tokio::process::Command::new(executable)
            .args([
                "--format",
                "jsonl",
                "--profile",
                profile_arg,
                "exec",
                "--conversation-id",
                conversation_id,
                "--workspace-id",
                workspace_id,
                "--prompt",
                "sigint fixture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn exec");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        Child {
            process: child,
            stdout_lines: BufReader::new(stdout),
            stderr: Some(stderr),
        }
    }

    async fn wait_submitted(child: &mut Child) -> String {
        loop {
            let mut line = String::new();
            let read = child
                .stdout_lines
                .read_line(&mut line)
                .await
                .expect("read stdout line");
            assert!(read > 0, "stdout closed before submitted event");
            let event: serde_json::Value =
                serde_json::from_str(line.trim_end()).expect("jsonl event");
            if event["type"] == "submitted" {
                return event["taskRunId"].as_str().expect("taskRunId").to_owned();
            }
        }
    }

    fn send_sigint(child: &Child) {
        let raw_pid = i32::try_from(child.process.id().expect("child pid")).expect("pid fits i32");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("valid pid");
        rustix::process::kill_process(pid, rustix::process::Signal::INT).expect("SIGINT delivered");
    }

    async fn read_cancel_requested(child: &mut Child) -> String {
        let mut output = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                let read = child
                    .stdout_lines
                    .read_line(&mut line)
                    .await
                    .expect("read stdout line");
                assert!(read > 0, "CLI closed before cancel request output");
                output.push_str(&line);
                if output.contains("\"type\":\"cancelRequested\"") {
                    break;
                }
            }
        })
        .await
        .expect("CLI emits cancel request within bound");
        output
    }

    async fn assert_second_sigint_exit(child: &mut Child, output: &mut String) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let mut line = String::new();
                let read = child
                    .stdout_lines
                    .read_line(&mut line)
                    .await
                    .expect("read stdout line");
                if read == 0 {
                    break;
                }
                output.push_str(&line);
            }
        })
        .await
        .expect("second SIGINT closes CLI stdout within bound");
        let status = tokio::time::timeout(std::time::Duration::from_secs(3), child.process.wait())
            .await
            .expect("second SIGINT exits within bound")
            .expect("run exec");
        assert_eq!(status.code(), Some(130), "escalation exits 130");
        assert!(output.contains("\"type\":\"cancelRequested\""), "{output}");
        assert!(
            !output.contains("\"type\":\"cancelAcknowledged\""),
            "{output}"
        );
        assert!(
            !output.contains("\"type\":\"cancelRequestFailed\""),
            "{output}"
        );
        assert!(!output.contains("\"type\":\"terminal\""), "{output}");
        let mut stderr = child.stderr.take().expect("stderr captured at spawn");
        let mut stderr_bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stderr.read_to_end(&mut stderr_bytes),
        )
        .await
        .expect("stderr closes within bound")
        .expect("read stderr");
        assert!(
            stderr_bytes.is_empty(),
            "held ACK does not create a terminal error"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_sigint_completes_proven_queued_cancellation() {
        let mut daemon = start_test_daemon().await;
        let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
        let client = connect_client(&daemon.profile).await;
        let (conversation_id, workspace_id) = seed_conversation(&client).await;

        let mut child = spawn_exec(
            &profile_arg,
            &conversation_id.to_string(),
            &workspace_id.to_string(),
        );
        let task_run_id = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_submitted(&mut child),
        )
        .await
        .expect("CLI submits taskrun within bound");
        send_sigint(&child);

        let mut rest = String::new();
        loop {
            let mut line = String::new();
            let read = child
                .stdout_lines
                .read_line(&mut line)
                .await
                .expect("read stdout line");
            if read == 0 {
                break;
            }
            rest.push_str(&line);
        }
        let status = child.process.wait().await.expect("run exec");
        assert_eq!(
            status.code(),
            Some(1),
            "a cancelled TaskRun is a non-success terminal outcome"
        );
        assert!(
            rest.contains("\"type\":\"cancelRequested\""),
            "the cancellation request is observable: {rest}"
        );
        assert!(
            rest.contains("\"type\":\"terminal\""),
            "the proven cancellation is reported as terminal"
        );
        assert!(rest.contains("\"state\":\"cancelled\""), "{rest}");
        let mut stderr = child.stderr.take().expect("stderr captured at spawn");
        let mut stderr_bytes = Vec::new();
        stderr
            .read_to_end(&mut stderr_bytes)
            .await
            .expect("read stderr");
        assert!(stderr_bytes.is_empty(), "terminal result is on stdout");

        // The queued cancellation is terminal only after the runtime proves
        // that no claim or provider dispatch occurred.
        let snapshots = client.list_task_runs().await.expect("list task runs");
        let cancelled = snapshots
            .iter()
            .find(|snapshot| snapshot.task_run_id().to_string() == task_run_id)
            .expect("submitted run found");
        assert_eq!(
            format!("{:?}", cancelled.state()),
            "Cancelled",
            "queued cancellation has no active effect to stop: {:?}",
            cancelled.state()
        );
        assert_eq!(cancelled.stream_version(), 4);

        stop_daemon(&mut daemon).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_sigint_exits_while_committed_cancel_ack_is_held() {
        let mut daemon = start_test_daemon().await;
        let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
        let client = connect_client(&daemon.profile).await;
        let (conversation_id, workspace_id) = seed_conversation(&client).await;

        let mut child = spawn_exec(
            &profile_arg,
            &conversation_id.to_string(),
            &workspace_id.to_string(),
        );
        let task_run_id = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_submitted(&mut child),
        )
        .await
        .expect("CLI submits taskrun within bound");
        let mut held_ack =
            runne_http::task_runs::test_support::hold_cancel_ack(task_run_id.clone())
                .expect("arm exact cancellation acknowledgement barrier");
        send_sigint(&child);
        // Wait until the first SIGINT is consumed (the cancelRequested event
        // is observable) so the escalation signal cannot coalesce with it.
        let mut rest = read_cancel_requested(&mut child).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            held_ack.wait_until_held(),
        )
        .await
        .expect("cancel request reached handler and committed")
        .expect("test barrier arrived");
        send_sigint(&child);

        assert_second_sigint_exit(&mut child, &mut rest).await;

        let scope = ReplayScope::new(
            ReplayAggregateKind::TaskRun,
            runne_runtime_client::CanonicalId::parse(&task_run_id).expect("taskrun ID"),
        );
        let mut history = Vec::new();
        let _live = client
            .catch_up(scope, None, |delivery| {
                let event = delivery.event();
                history.push((
                    event.event_id(),
                    event.sequence(),
                    event.event_type().to_owned(),
                ));
                Ok::<(), ()>(())
            })
            .await
            .expect("read verified TaskRun history after CLI exit");
        let snapshots = client.list_task_runs().await.expect("list task runs");
        let run = snapshots
            .iter()
            .find(|snapshot| snapshot.task_run_id().to_string() == task_run_id)
            .expect("submitted run found");
        let cancellation = history
            .iter()
            .filter(|(_, _, event_type)| event_type == "taskRun.cancellation.requested")
            .collect::<Vec<_>>();
        assert_eq!(cancellation.len(), 1, "one durable cancellation request");
        assert_eq!(cancellation[0].1, 3, "exact cancellation event version");
        match format!("{:?}", run.state()).as_str() {
            "Cancelling" => assert_eq!(run.stream_version(), cancellation[0].1),
            "Cancelled" => assert!(history.iter().any(|(_, version, event_type)| {
                *version > cancellation[0].1
                    && (event_type == "taskRun.cancelled"
                        || event_type == "taskRun.cancellation.completed")
            })),
            state => panic!("unexpected state after accepted queued cancel: {state}"),
        }
        assert_ne!(format!("{:?}", run.state()), "Succeeded");
        held_ack.release();

        stop_daemon(&mut daemon).await;
    }
}

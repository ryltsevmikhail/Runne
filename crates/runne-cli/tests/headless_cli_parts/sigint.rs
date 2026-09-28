//! Bounded-SIGINT scenarios: the real CLI binary execs against a live
//! daemon; the first SIGINT requests durable cancellation, the second exits
//! immediately without a terminal claim.

#![cfg(unix)]

pub mod sigint_scenario {
    use crate::support::{connect_client, seed_conversation, start_test_daemon, stop_daemon};
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

    async fn parse_json_error_envelope_from_stderr(mut child: Child) -> serde_json::Value {
        let mut stderr = child.stderr.take().expect("stderr captured at spawn");
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.expect("read stderr");
        let envelope: serde_json::Value =
            serde_json::from_slice(&bytes).expect("JSON error envelope");
        assert_eq!(envelope["ok"], false);
        envelope
    }

    fn send_sigint(child: &Child) {
        let raw_pid = i32::try_from(child.process.id().expect("child pid")).expect("pid fits i32");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("valid pid");
        rustix::process::kill_process(pid, rustix::process::Signal::INT).expect("SIGINT delivered");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_sigint_requests_cancellation_and_exits_cancel_pending() {
        let mut daemon = start_test_daemon().await;
        let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
        let client = connect_client(&daemon.profile).await;
        let (conversation_id, workspace_id) = seed_conversation(&client).await;

        let mut child = spawn_exec(
            &profile_arg,
            &conversation_id.to_string(),
            &workspace_id.to_string(),
        );
        let task_run_id = wait_submitted(&mut child).await;
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
            Some(5),
            "grace expiry without terminal is the typed pending exit"
        );
        assert!(
            rest.contains("\"type\":\"cancelRequested\""),
            "the cancellation request is observable: {rest}"
        );
        assert!(
            !rest.contains("\"type\":\"terminal\""),
            "no terminal is claimed without terminal evidence"
        );
        let envelope = parse_json_error_envelope_from_stderr(child).await;
        assert_eq!(envelope["error"]["code"], "cancel_pending");

        // The durable cancellation request is visible to the runtime, without
        // a terminal outcome claim.
        let snapshots = client.list_task_runs().await.expect("list task runs");
        let cancelled = snapshots
            .iter()
            .find(|snapshot| snapshot.task_run_id().to_string() == task_run_id)
            .expect("submitted run found");
        assert_eq!(
            format!("{:?}", cancelled.state()),
            "Cancelling",
            "durable cancellation requested, not terminal: {:?}",
            cancelled.state()
        );

        stop_daemon(&mut daemon).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_sigint_exits_immediately_without_terminal_claim() {
        let mut daemon = start_test_daemon().await;
        let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
        let client = connect_client(&daemon.profile).await;
        let (conversation_id, workspace_id) = seed_conversation(&client).await;

        let mut child = spawn_exec(
            &profile_arg,
            &conversation_id.to_string(),
            &workspace_id.to_string(),
        );
        let task_run_id = wait_submitted(&mut child).await;
        send_sigint(&child);
        // Wait until the first SIGINT is consumed (the cancelRequested event
        // is observable) so the escalation signal cannot coalesce with it.
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
            if rest.contains("\"type\":\"cancelRequested\"") {
                break;
            }
        }
        send_sigint(&child);

        let started = std::time::Instant::now();
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
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "second SIGINT exits immediately"
        );
        assert_eq!(status.code(), Some(130), "escalation exits 130");
        assert!(!rest.contains("\"type\":\"terminal\""), "{rest}");

        let snapshots = client.list_task_runs().await.expect("list task runs");
        let run = snapshots
            .iter()
            .find(|snapshot| snapshot.task_run_id().to_string() == task_run_id)
            .expect("submitted run found");
        assert_ne!(
            format!("{:?}", run.state()),
            "Succeeded",
            "escalation never fakes a terminal outcome"
        );

        stop_daemon(&mut daemon).await;
    }
}

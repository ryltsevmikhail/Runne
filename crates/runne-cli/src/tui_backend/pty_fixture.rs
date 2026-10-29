//! Manual PTY integration entry compiled exclusively into the Rust test binary.
use std::{io::IsTerminal as _, path::PathBuf};

fn directory(variable: &str) -> PathBuf {
    let value = PathBuf::from(std::env::var_os(variable).expect("explicit fixture directory"));
    assert!(value.is_absolute(), "fixture directory must be absolute");
    let canonical = value.canonicalize().expect("existing fixture directory");
    assert_eq!(canonical, value, "fixture directory must be canonical");
    assert!(canonical.is_dir());
    canonical
}

#[test]
#[ignore = "requires explicitly marked synthetic runtime and an interactive PTY"]
fn real_backend_terminal() {
    assert_eq!(
        std::env::var("RUNNE_TEST_TERMINAL_AGENT_FIXTURE").as_deref(),
        Ok("1")
    );
    let base = directory("RUNNE_TEST_TERMINAL_AGENT_BASE");
    let root = directory("RUNNE_TEST_TERMINAL_AGENT_ROOT");
    let project = directory("RUNNE_TEST_TERMINAL_AGENT_PROJECT");
    let state = directory("XDG_STATE_HOME");
    assert!(root.starts_with(&base) && root != base);
    assert!(project.starts_with(&base) && project != base);
    assert!(state.starts_with(&base) && state != base);
    assert!(!root.starts_with(&project) && !project.starts_with(&root));
    let marker = root.join(".terminal-agent-test-fixture");
    let metadata = marker
        .symlink_metadata()
        .expect("explicit synthetic fixture marker");
    assert!(metadata.is_file() && metadata.len() <= 64);
    assert_eq!(
        std::fs::read_to_string(marker).unwrap().trim(),
        "loopback-only-v1"
    );
    assert!(
        root.join("fixture-config").is_dir(),
        "synthetic fixture config required"
    );
    assert!(std::io::stdin().is_terminal() && std::io::stdout().is_terminal());
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (result, cleanup) = runne_runtime_client::with_local_session_cleanup(Box::pin(async {
            let owner = Box::pin(super::owner::start_protected(root, project, None)).await?;
            if std::env::var("RUNNE_TEST_TERMINAL_AGENT_EFFECT_REPORT").as_deref() == Ok("1") {
                for task in owner.client.list_task_runs().await.map_err(|e| e.to_string())? {
                    let effects = owner.client.get_task_run_effects(task.task_run_id())
                        .await.map_err(|e| e.to_string())?;
                    println!("fixture task={} state={:?} cancel={} remote={:?} remote_cancel={:?} local={:?}",
                        task.task_run_id(), task.state(), effects.cancellation_requested(),
                        effects.remote().outcome(), effects.remote().cancellation(),
                        effects.local_command().map(|local| (local.outcome(), local.stop())));
                }
                return Ok::<(), String>(());
            }
            Box::pin(super::run_with_owner(owner, None, false)).await
        }))
        .await;
        cleanup.expect("fixture session cleanup");
        result.expect("real terminal backend completed");
    });
}

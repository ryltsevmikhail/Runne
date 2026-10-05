use super::{cancel_final, stale_final, verify};

pub(super) struct Fixture<'a> {
    pub(super) client: &'a runne_runtime_client::AuthenticatedRuntimeClient,
    pub(super) task: runne_runtime_client::CanonicalId,
    pub(super) conversation: runne_runtime_client::CanonicalId,
    pub(super) read_path: &'a std::path::Path,
    pub(super) create_path: &'a std::path::Path,
    pub(super) read_watch: &'a std::fs::File,
    pub(super) create_watch: &'a std::fs::File,
    pub(super) database: &'a std::path::Path,
    pub(super) runtime_root: &'a std::path::Path,
    pub(super) supervisor: &'a mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    pub(super) executable: &'a std::path::Path,
    pub(super) session_bus_socket: &'a std::path::Path,
}

pub(super) async fn dispatch(f: Fixture<'_>) -> bool {
    match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
        Ok("budget-exhausted") => {
            let failed = verify::wait_success(f.client, f.task, f.database, f.runtime_root).await;
            assert_eq!(failed.state(), runne_runtime_client::TaskRunState::Failed);
            super::super::faults::assert_failure_projection(f.database, f.task);
            verify::assert_encrypted_results(f.database, f.task, 2);
            verify::assert_request_counts(f.runtime_root);
            assert_eq!(verify::invocation_count(f.database, f.task), 2);
            assert_eq!(verify::reserved_effect_count(f.database, f.task), 2);
            assert_eq!(verify::release_intent_count(f.database, f.task), 2);
            assert_eq!(
                super::super::diagnostic::count_watch_mask(f.read_watch, libc::IN_OPEN),
                0
            );
            assert_eq!(
                super::super::diagnostic::count_watch_mask(f.create_watch, libc::IN_CREATE),
                0
            );
            assert!(f.create_path.is_file());
            assert!(
                f.client
                    .list_pending_approvals()
                    .await
                    .expect("read pending approvals")
                    .into_iter()
                    .all(|row| row.task_run_id() != f.task)
            );
            eprintln!("PASS: finite tool budget rejected third proposal before helper launch");
            true
        }
        Ok("stale-final-target") => {
            stale_final::exercise(
                f.client,
                f.task,
                f.read_path,
                f.create_path,
                f.read_watch,
                f.create_watch,
                f.database,
                f.runtime_root,
            )
            .await;
            true
        }
        Ok("cancel-final-response") => {
            cancel_final::exercise(
                f.client,
                f.task,
                f.conversation,
                f.database,
                f.runtime_root,
                f.supervisor,
                f.executable,
                f.session_bus_socket,
            )
            .await;
            assert_eq!(
                super::super::diagnostic::count_watch_mask(f.read_watch, libc::IN_OPEN),
                0,
                "both same-root reopens did not repeat the approved read"
            );
            assert_eq!(
                super::super::diagnostic::count_watch_mask(f.create_watch, libc::IN_CREATE),
                0,
                "both same-root reopens did not repeat the approved create"
            );
            assert_eq!(
                std::fs::read(f.read_path).expect("read unchanged fixture input"),
                b"approved fixture bytes\n"
            );
            assert_eq!(
                std::fs::read(f.create_path).expect("read preserved created output"),
                b"created through approved tool\n"
            );
            true
        }
        _ => false,
    }
}

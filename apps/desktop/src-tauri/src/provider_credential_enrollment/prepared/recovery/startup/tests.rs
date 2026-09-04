use super::*;

#[tokio::test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "assert real lease and reaper lifecycle through explicit cleanup"
)]
async fn native_startup_skips_existing_v3_without_preparing_a_new_transition() {
    let directory = tempfile::tempdir().unwrap();
    let updater =
        crate::updater_status::enrollment::test_only_current_enrollment_updater(directory.path())
            .await;
    let mut runtime = crate::bundled_runtime::test_only_live_enrollment_runtime(
        directory.path(),
        runne_platform_desktop::test_only_ready_v3_enrollment_supervisor(),
    )
    .await;
    let (lease, cleanup) = runtime.take_lease_with_cleanup();
    let mut native = NativeStartup {
        runtime: Arc::new(lease),
        updater: Arc::new(updater.lease),
        recovered: None,
    };
    assert_eq!(run(&mut native).await, Ok(()));
    assert!(native.recovered.is_none());
    drop(native);
    assert!(runtime.operation_available());
    cleanup.abort().await;
    assert!(runtime.writer_reaper_registry().shutdown());
}

struct Steps {
    pending: Option<Vec<[u8; 16]>>,
    fail: Option<&'static str>,
    log: Vec<&'static str>,
    selected: Option<[u8; 16]>,
}
impl Steps {
    fn step(&mut self, name: &'static str) -> Result<(), RecoveryRunError> {
        self.log.push(name);
        if self.fail == Some(name) {
            Err(RecoveryRunError::Transport)
        } else {
            Ok(())
        }
    }
}
impl StartupSteps for Steps {
    async fn discover(&mut self) -> Result<Option<Vec<[u8; 16]>>, RecoveryRunError> {
        self.step("discover")?;
        Ok(self.pending.take())
    }
    async fn first(&mut self, operation: [u8; 16]) -> Result<(), RecoveryRunError> {
        self.selected = Some(operation);
        self.step("first")
    }
    async fn drain(&mut self) -> Result<(), RecoveryRunError> {
        self.step("drain")
    }
}

#[tokio::test]
async fn startup_without_pending_work_never_transitions_or_runs_writer() {
    for pending in [None, Some(vec![])] {
        let mut steps = Steps {
            pending,
            fail: None,
            log: vec![],
            selected: None,
        };
        assert_eq!(run(&mut steps).await, Ok(()));
        assert_eq!(steps.log, ["discover"]);
        assert_eq!(steps.selected, None);
    }
}

#[tokio::test]
async fn startup_runs_first_cleanup_before_normal_scheduler_and_short_circuits_errors() {
    for fail in [None, Some("discover"), Some("first"), Some("drain")] {
        let mut steps = Steps {
            pending: Some(vec![[7; 16], [8; 16]]),
            fail,
            log: vec![],
            selected: None,
        };
        assert_eq!(run(&mut steps).await.is_ok(), fail.is_none());
        let expected: &[&str] = match fail {
            Some("discover") => &["discover"],
            Some("first") => &["discover", "first"],
            _ => &["discover", "first", "drain"],
        };
        assert_eq!(steps.log, expected);
        if fail != Some("discover") {
            assert_eq!(steps.selected, Some([7; 16]));
        }
    }
}

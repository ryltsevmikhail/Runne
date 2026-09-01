    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{
        BundledRuntimeController, ProtectedSessionRenewalSchedule, RuntimeOperationFence,
        map_protected_failure,
    };
    use runne_api::ProviderActivationReadinessV1;
    use runne_app_core::{AppCore, RuntimeFailureCode, RuntimeMode};
    use runne_platform_desktop::ProtectedBundledRuntimeError;

    #[test]
    fn protected_failures_map_to_closed_renderer_codes() {
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ExecutableUnavailable),
            RuntimeFailureCode::BundledExecutableUnavailable
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::OwnershipMismatch),
            RuntimeFailureCode::ProtectedReadinessRejected
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::RestartExhausted),
            RuntimeFailureCode::BundledRestartExhausted
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::UnsupportedPlatformBackend),
            RuntimeFailureCode::UnsupportedPlatformBackend
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ProviderActivationNotReady(
                ProviderActivationReadinessV1::CredentialMissing,
            )),
            RuntimeFailureCode::ConfigurationRequired
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ProviderActivationNotReady(
                ProviderActivationReadinessV1::CredentialAccessDenied,
            )),
            RuntimeFailureCode::BundledExecutableIdentityMismatch
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ProviderActivationNotReady(
                ProviderActivationReadinessV1::CredentialIdentityMismatch,
            )),
            RuntimeFailureCode::BundledExecutableIdentityMismatch
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ProviderActivationNotReady(
                ProviderActivationReadinessV1::SecureStoreUnavailable,
            )),
            RuntimeFailureCode::ProtectedActivationUnavailable
        );
    }

    #[tokio::test]
    async fn default_bundled_discovery_rejects_missing_packaged_runtime() {
        let temporary = tempfile::tempdir().expect("temporary profile");
        let core = Arc::new(
            AppCore::open_with_runtime_mode(
                &temporary.path().join("profile.sqlite3"),
                RuntimeMode::Bundled,
            )
            .expect("open bundled core"),
        );

        let Err(failure) = BundledRuntimeController::discover(
            Arc::clone(&core),
            temporary.path().join("runne-desktop").as_path(),
            temporary.path().join("bundled-runtime").as_path(),
        ) else {
            panic!("default bundled discovery must reject missing runtime");
        };
        assert_eq!(failure, RuntimeFailureCode::BundledExecutableUnavailable);
        core.mark_bundled_runtime_failed(failure)
            .await
            .expect("mark missing packaged runtime");

        let bootstrap = core.bootstrap().expect("configuration bootstrap");
        assert_eq!(bootstrap.runtime, runne_app_core::RuntimeAvailability::Fatal);
        assert_eq!(
            bootstrap.runtime_lifecycle,
            runne_app_core::RuntimeLifecycleStatus::Failed
        );
        assert_eq!(
            bootstrap.runtime_failure,
            Some(RuntimeFailureCode::BundledExecutableUnavailable)
        );
    }

    #[test]
    fn protected_session_renewal_schedule_is_early_and_rearmable() {
        let now = Instant::now();
        let mut schedule = ProtectedSessionRenewalSchedule::new(Duration::from_millis(20));

        assert!(schedule.is_due(now));
        schedule.arm(now);
        assert!(!schedule.is_due(now + Duration::from_millis(19)));
        assert!(schedule.is_due(now + Duration::from_millis(20)));
        schedule.arm(now + Duration::from_millis(20));
        assert!(!schedule.is_due(now + Duration::from_millis(39)));
        assert!(schedule.is_due(now + Duration::from_millis(40)));
        schedule.clear();
        assert!(schedule.is_due(now));
    }

    #[test]
    fn shutdown_fence_waits_for_inflight_install_and_rejects_new_work() {
        let fence = Arc::new(RuntimeOperationFence::new());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_fence = Arc::clone(&fence);
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let operation = worker_fence.enter().await.expect("enter operation");
                entered_tx.send(()).expect("signal entered");
                release_rx.recv().expect("release operation");
                drop(operation);
            });
        });
        entered_rx.recv().expect("operation entered");

        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let shutdown_fence = Arc::clone(&fence);
        let shutdown = std::thread::spawn(move || {
            assert!(shutdown_fence.begin_shutdown());
            let _idle = shutdown_fence.wait_for_idle();
            shutdown_tx.send(()).expect("signal shutdown");
        });
        assert!(shutdown_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release_tx.send(()).expect("release operation");
        shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown acquires fence");
        worker.join().expect("worker");
        shutdown.join().expect("shutdown");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        assert!(runtime.block_on(fence.enter()).is_none());
        assert!(!fence.begin_shutdown());
    }

    #[test]
    fn enrollment_lease_owns_the_appcore_generation_fence() {
        let source = include_str!("../bundled_runtime.rs");
        let lease = source
            .split("pub struct NativeCredentialEnrollmentLease")
            .nth(1)
            .expect("lease definition");
        assert!(lease.contains("core: Arc<AppCore>"));
        let transition = source
            .find("transition_and_install")
            .expect("atomic transition/install path");
        let restart = source[transition..]
            .find("begin_bundled_runtime_restart")
            .expect("old AppCore client fenced");
        let install = source[transition..]
            .find("install_bundled_runtime_client")
            .expect("rotated client installed");
        assert!(restart < install);
    }

    #[test]
    fn every_post_fence_transition_failure_enters_cleanup() {
        let source = include_str!("../bundled_runtime.rs");
        let transition = source
            .split("pub(crate) async fn transition_and_install")
            .nth(1)
            .expect("transition method");
        let body = transition
            .split("async fn install_transitioned_profile")
            .next()
            .expect("outer transition body");
        assert!(body.contains("let transition = self"));
        assert!(body.contains("Err(_) => self.fail_transition().await"));
        assert_eq!(body.matches("begin_bundled_runtime_restart").count(), 1);
    }

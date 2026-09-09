    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{
        BundledRuntimeController, ProtectedSessionRenewalSchedule, RuntimeOperationFence,
        map_protected_failure,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use super::acquire_fenced_enrollment_permit;
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[tokio::test]
    async fn enrollment_reaper_admission_is_checked_after_the_operation_fence() {
        let fence = Arc::new(RuntimeOperationFence::new());
        let held_permit = fence.enter().await.expect("hold operation fence");
        let accepts_writer = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let candidate_fence = Arc::clone(&fence);
        let candidate_accepts_writer = Arc::clone(&accepts_writer);
        let (checked_tx, mut checked_rx) = tokio::sync::oneshot::channel();
        let candidate = tokio::spawn(async move {
            acquire_fenced_enrollment_permit(&candidate_fence, move || {
                let _ = checked_tx.send(());
                candidate_accepts_writer.load(std::sync::atomic::Ordering::SeqCst)
            })
            .await
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut checked_rx)
                .await
                .is_err(),
            "a queued request must not inspect reaper state before it owns the fence"
        );
        accepts_writer.store(false, std::sync::atomic::Ordering::SeqCst);
        drop(held_permit);
        checked_rx.await.expect("reaper state checked after fence");
        assert!(
            candidate.await.expect("candidate task").is_err(),
            "a retained writer must reject the next queued enrollment"
        );
    }

    #[test]
    fn enrollment_lease_owns_the_appcore_generation_fence() {
        let source = include_str!("../bundled_runtime.rs");
        let enrollment = include_str!("enrollment.rs");
        let lease = source
            .split("pub struct NativeCredentialEnrollmentLease")
            .nth(1)
            .expect("lease definition");
        assert!(lease.contains("core: Arc<AppCore>"));
        let transition = enrollment
            .find("transition_and_install")
            .expect("atomic transition/install path");
        let restart = enrollment[transition..]
            .find("begin_bundled_runtime_restart")
            .expect("old AppCore client fenced");
        let install = enrollment[transition..]
            .find("install_bundled_runtime_client")
            .expect("rotated client installed");
        assert!(restart < install);
    }

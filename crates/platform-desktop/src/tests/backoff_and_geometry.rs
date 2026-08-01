    #[test]
    fn bundled_runtime_backoff_is_bounded_and_stable_authenticated_readiness_resets_the_budget() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        for (index, seconds) in [1, 2, 5, 10, 30].into_iter().enumerate() {
            assert_eq!(
                backoff.record_unexpected_exit(start + Duration::from_secs(index as u64)),
                BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(5)),
            BundledRuntimeRestartDisposition::Exhausted
        );

        backoff.record_authenticated_ready(start + Duration::from_secs(6));
        assert!(!backoff.reset_after_stable_readiness(start + Duration::from_secs(599)));
        assert!(
            backoff.reset_after_stable_readiness(
                start + Duration::from_secs(6) + UNEXPECTED_EXIT_WINDOW
            )
        );
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(6) + UNEXPECTED_EXIT_WINDOW),
            BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(1))
        );
    }

    #[test]
    fn bundled_runtime_backoff_requires_continuous_authenticated_readiness() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        backoff.record_authenticated_ready(start);
        backoff.record_disconnected();
        backoff.record_authenticated_ready(start + Duration::from_secs(1));

        assert!(!backoff.reset_after_stable_readiness(start + UNEXPECTED_EXIT_WINDOW));
        assert!(
            backoff.reset_after_stable_readiness(
                start + Duration::from_secs(1) + UNEXPECTED_EXIT_WINDOW
            )
        );

        backoff.record_authenticated_ready(start + UNEXPECTED_EXIT_WINDOW);
        let _ =
            backoff.record_unexpected_exit(start + UNEXPECTED_EXIT_WINDOW + Duration::from_secs(1));
        assert!(
            !backoff.reset_after_stable_readiness(
                start + UNEXPECTED_EXIT_WINDOW + UNEXPECTED_EXIT_WINDOW
            )
        );
    }

    #[test]
    fn bundled_runtime_backoff_enforces_the_rolling_ten_minute_exit_window() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        for seconds in [1, 2, 5, 10, 30] {
            assert_eq!(
                backoff.record_unexpected_exit(start),
                BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(599)),
            BundledRuntimeRestartDisposition::Exhausted
        );
        assert_eq!(
            backoff.record_unexpected_exit(start + UNEXPECTED_EXIT_WINDOW),
            BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(1))
        );
    }

    #[test]
    fn profile_lock_rejects_a_concurrent_owner_and_recovers_after_drop() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.lock");

        let first = ProfileLock::acquire(&path).expect("acquire first owner");
        let error = ProfileLock::acquire(&path).expect_err("reject second owner");
        assert_eq!(error.to_string(), "profile is already owned");

        drop(first);
        ProfileLock::acquire(&path).expect("lock released with owner");
    }

    #[test]
    fn restored_window_is_clamped_to_the_current_display_work_area() {
        let work_area = DisplayWorkArea {
            x: 0,
            y: 24,
            width: 1_920,
            height: 1_056,
        };
        let stored = WindowGeometry {
            x: 2_100,
            y: -400,
            width: 2_400,
            height: 1_400,
        };

        assert_eq!(
            restore_window_geometry(stored, work_area),
            WindowGeometry {
                x: 0,
                y: 24,
                width: 1_920,
                height: 1_056,
            }
        );
    }

    #[test]
    fn invalid_or_too_small_geometry_uses_the_documented_safe_default() {
        let work_area = DisplayWorkArea {
            x: 0,
            y: 0,
            width: 1_600,
            height: 900,
        };
        let stored = WindowGeometry {
            x: 50,
            y: 50,
            width: 100,
            height: 100,
        };

        assert_eq!(
            restore_window_geometry(stored, work_area),
            WindowGeometry {
                x: 80,
                y: 0,
                width: 1_440,
                height: 900,
            }
        );
    }

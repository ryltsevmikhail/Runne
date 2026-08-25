use super::*;

fn binding() -> UpdateTargetBindingConfig {
    UpdateTargetBindingConfig {
        product_id: "com.runne.desktop".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        min_os: "ubuntu-22.04".into(),
        profile_id: "profile".into(),
        bundle_sha256: "a".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "b".repeat(64),
        channel: "stable".into(),
    }
}

fn coordinator(directory: &Path) -> UpdateCoordinator {
    UpdateCoordinator::new(
        UpdateTrustRootV2::from_keys(
            [
                ("root-a", [1; 32]),
                ("root-b", [2; 32]),
                ("root-c", [3; 32]),
            ],
            ("timestamp", [4; 32]),
            ("snapshot", [5; 32]),
        ),
        binding(),
        directory,
    )
    .unwrap()
}

fn record(coordinator: &UpdateCoordinator, directory: &Path) {
    coordinator
        .journal
        .record_staged(
            "1.2.0",
            &StagedUpdate {
                path: directory.join("staged.update"),
                artifact_sha256: "c".repeat(64),
            },
        )
        .unwrap();
}

#[test]
fn coordinator_requires_confirmation_and_persists_healthy_install() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    assert_eq!(
        coordinator.prepare_restart(1, false),
        Err(UpdateCoordinatorError::ActiveTaskRuns)
    );
    coordinator
        .trust_journal
        .initialize("1.0.0", "1.0.0")
        .unwrap();
    assert_eq!(
        coordinator.prepare_restart(1, true).unwrap().state,
        UpdateInstallState::RestartRequired
    );
    coordinator.begin_health_check().unwrap();
    assert_eq!(
        coordinator.complete_health(true, "1.2.0").unwrap().state,
        UpdateInstallState::Committed
    );
    assert_eq!(
        coordinator
            .trust_journal
            .read()
            .unwrap()
            .unwrap()
            .installed_version,
        "1.2.0"
    );
}

#[test]
fn coordinator_persists_explicit_rollback_after_failed_health() {
    let directory = tempfile::tempdir().unwrap();
    let coordinator = coordinator(directory.path());
    record(&coordinator, directory.path());
    coordinator.prepare_restart(0, false).unwrap();
    coordinator.begin_health_check().unwrap();
    assert_eq!(
        coordinator.complete_health(false, "1.2.0").unwrap().state,
        UpdateInstallState::RolledBack
    );
}

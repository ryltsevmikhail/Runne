use super::*;
use crate::provider::ProviderCoordinatorOutcome;
use runne_application::provider::ProviderAdmissionError;

#[test]
fn newer_launch_before_issue_rejects_stale_capability_before_replay() {
    let fixture = OverlapFixture::new(101, "launch-before-issue");
    let launch_n = fixture
        .execution
        .activate_runtime_launch(&config())
        .unwrap();
    super::super::online_proof_test_support::arm(&fixture.execution);
    let _launch_n1 = fixture
        .execution
        .activate_runtime_launch(&next_config())
        .unwrap();
    let effect = Effect::default();
    let coordinator = fixture.coordinator(&launch_n, &effect);
    let request = coordinator_request(101, "launch-before-issue", &fixture.path);

    assert_eq!(
        block_on(coordinator.dispatch(request)),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    assert_eq!(effect.materialized.load(Ordering::SeqCst), 0);
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(durable_counts(&fixture.path), (0, 0, 0, 0, 0, 0));
}

#[test]
fn same_generation_recomposition_before_online_authorization_mints_no_binding_or_effect() {
    let fixture = OverlapFixture::new(103, "same-generation-online");
    let launch_n = fixture
        .execution
        .activate_runtime_launch(&config())
        .unwrap();
    super::super::online_proof_test_support::arm(&fixture.execution);
    let effect = Effect::default();
    let (reached, release) = fixture.lifecycle.pause_before_online_authorization();
    let coordinator = fixture.coordinator(&launch_n, &effect);
    let request = coordinator_request(103, "same-generation-online", &fixture.path);

    std::thread::scope(|scope| {
        let worker = scope.spawn(move || block_on(coordinator.dispatch(request)));
        reached.wait();
        let _launch_n1 = fixture
            .execution
            .activate_runtime_launch(&config())
            .unwrap();
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            ProviderCoordinatorOutcome::RejectedBeforeEffect {
                reason: runne_provider::ProviderPreEffectRejection::AdapterRejected,
            }
        );
    });

    assert_eq!(effect.materialized.load(Ordering::SeqCst), 0);
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(durable_counts(&fixture.path), (1, 1, 1, 0, 0, 0));
}

#[test]
fn newer_launch_after_materialization_rejects_before_effect_start() {
    let fixture = OverlapFixture::new(102, "launch-before-effect");
    let launch_n = fixture
        .execution
        .activate_runtime_launch(&config())
        .unwrap();
    super::super::online_proof_test_support::arm(&fixture.execution);
    let effect = Effect::default();
    let (reached, release) = effect.pause_after_stage();
    let coordinator = fixture.coordinator(&launch_n, &effect);
    let request = coordinator_request(102, "launch-before-effect", &fixture.path);

    std::thread::scope(|scope| {
        let worker = scope.spawn(move || block_on(coordinator.dispatch(request)));
        reached.wait();
        let _launch_n1 = fixture
            .execution
            .activate_runtime_launch(&next_config())
            .unwrap();
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap(),
            ProviderCoordinatorOutcome::Uncertain
        );
    });

    assert_eq!(effect.materialized.load(Ordering::SeqCst), 1);
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(durable_counts(&fixture.path), (1, 1, 1, 0, 0, 0));
}

struct OverlapFixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    dispatch: SqliteProviderDispatchStore,
    execution: SqliteProviderExecutionStore,
    lifecycle: crate::provider::SqliteProviderCredentialLifecycleStore,
}

impl OverlapFixture {
    fn new(discriminator: u8, key: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        secure_directory(directory.path());
        secure_directory(&daemon);
        let path = daemon.join(format!("{key}.sqlite"));
        let lifecycle = open_test_store(&path, 100);
        complete_pair(&lifecycle, discriminator, key);
        let text = path.to_str().unwrap();
        let dispatch =
            SqliteProviderDispatchStore::open_with_connection(text, configured_connection(&path))
                .unwrap();
        let execution =
            SqliteProviderExecutionStore::open_with_connection(text, configured_connection(&path))
                .unwrap();
        Self {
            _directory: directory,
            path,
            dispatch,
            execution,
            lifecycle,
        }
    }

    fn coordinator<'a>(
        &'a self,
        launch: &'a crate::provider::ProviderRuntimeLaunchCapability,
        effect: &'a Effect,
    ) -> SqliteProviderDispatchCoordinator<'a, Effect, Effect> {
        SqliteProviderDispatchCoordinator::new(
            &self.dispatch,
            &self.execution,
            CredentialDispatchAuthority::new(&self.lifecycle, launch),
            effect,
            effect,
            &Guard,
        )
    }
}

fn next_config() -> crate::provider::ProviderRuntimeAuthorityConfig {
    let mut next = config();
    next.generation += 1;
    next.fencing_token += 1;
    next
}

fn durable_counts(path: &std::path::Path) -> (i64, i64, i64, i64, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_prepared_requests),
                (SELECT COUNT(*) FROM provider_execution_admissions),
                (SELECT COUNT(*) FROM provider_online_dispatch_claim_providers),
                (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM provider_online_credential_effect_bindings),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap()
}

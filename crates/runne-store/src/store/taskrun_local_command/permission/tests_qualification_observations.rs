//! Real prepared observations, synthetic area/callback: Store MODEL, never native GO.
use super::{fixture::Fixture, support::Case};
use runne_application::ports::EventStoreError;
use runne_domain::task_run::TaskRunLocalCommand;
use runne_platform::local_command_linux::{PreparedPermissionTargetV1, SealedExecutableSnapshot};
use std::fs::File;

fn prepare(c: &Case, kind: u8) -> PreparedPermissionTargetV1 {
    let command = if kind == 1 {
        TaskRunLocalCommand::new(
            c.b.command().executable().clone(),
            c.b.command().cwd().into(),
            c.b.command().argv().to_vec(),
            vec![("MODEL_ACCOUNT".into(), "other-account".into())],
        )
        .unwrap()
    } else {
        c.b.command().clone()
    };
    let cwd_path = c.f.root.path().join("workspace/other-cwd");
    if kind == 2 {
        std::fs::create_dir(&cwd_path).unwrap();
    }
    let cwd = if kind == 2 {
        File::open(cwd_path).unwrap()
    } else {
        c.f.held.try_clone().unwrap()
    };
    let path = c.f.root.path().join("workspace/tool");
    let snapshot = SealedExecutableSnapshot::from_held_file(&File::open(path).unwrap()).unwrap();
    c.f.store
        .local_permission_preparation()
        .unwrap()
        .prepare_target(command, &c.f.held, &cwd, snapshot)
        .unwrap()
}

fn refuses_then_original_reaches_once(kind: u8) {
    let c = Case::new(true);
    let other = prepare(&c, kind);
    let original = c.prepared.observation();
    let changed = other.observation();
    assert_eq!(changed.owner_id(), original.owner_id());
    assert_eq!(changed.owner_generation(), original.owner_generation());
    assert_ne!(changed.target_identity(), original.target_identity());
    if kind == 1 {
        assert_ne!(changed.environment_digest(), original.environment_digest());
    }
    if kind == 2 {
        assert_ne!(changed.cwd_identity(), original.cwd_identity());
    }
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert_eq!(
        c.release_observed(lease.as_ref(), 0, changed),
        (Err(EventStoreError::CorruptData), 0)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
    // Refusal did not consume the callback or replace the original prepared target.
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
}

#[test]
fn fresh_sealed_target_same_owner_refuses_original_grant() {
    refuses_then_original_reaches_once(0);
}

#[test]
fn prepared_environment_account_digest_drift_refuses_original_grant() {
    // Account is represented only as existing command environment digest, not a new identity field.
    // Fresh sealed target also differs; this does NOT isolate the environment comparator.
    refuses_then_original_reaches_once(1);
}

#[test]
fn prepared_cwd_drift_refuses_original_grant() {
    // New held cwd and sealed target both differ; no fabricated observation fields.
    refuses_then_original_reaches_once(2);
}

#[test]
fn actual_foreign_registered_owner_observation_refuses_original_grant() {
    let c = Case::new(true);
    let foreign = Fixture::new();
    let snapshot = SealedExecutableSnapshot::from_held_file(
        &File::open(c.f.root.path().join("workspace/tool")).unwrap(),
    )
    .unwrap();
    let prepared = foreign
        .store
        .local_permission_preparation()
        .unwrap()
        .prepare_target(c.b.command().clone(), &c.f.held, &c.f.held, snapshot)
        .unwrap();
    assert_ne!(
        prepared.observation().owner_id(),
        c.prepared.observation().owner_id()
    );
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(
        c.release_observed(lease.as_ref(), 0, prepared.observation()),
        (Err(EventStoreError::CorruptData), 0)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
}

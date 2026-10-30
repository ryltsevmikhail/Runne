use super::*;

fn completed(name: &str, legacy: bool, runtime_actor: &str) -> (Database, TaskRunId) {
    let db = Database::new(name);
    create_project(&db.repository());
    create_workspace(&db.repository());
    let taskrun_id = if legacy {
        submit_legacy(&db, 0x41).0
    } else {
        let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
            submit_task_run(&db, 0x41, "queued-proof-submit")
        else {
            panic!("submit")
        };
        taskrun_id
    };
    db.task_runs()
        .cancel_task_run(
            &task_context(0x71, "queued-proof-cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let mut completion = task_context(0x72, "queued-proof-complete");
    if !runtime_actor.is_empty() {
        completion.principal_id = runne_application::ports::PrincipalId("runne-runtime".into());
        completion.actor = runne_domain::event::Actor::new(runtime_actor).unwrap();
    }
    db.task_runs()
        .complete_queued_cancellation(
            &completion,
            CompleteQueuedCancellationInput {
                taskrun_id,
                expected_version: 3,
            },
            &db.store,
        )
        .unwrap();
    (db, taskrun_id)
}

#[test]
fn queued_legacy_and_v2_cancellation_prove_remote_not_started_after_reopen() {
    for legacy in [true, false] {
        let (db, task) = completed("queued-effect-proven", legacy, "");
        let reopened = crate::validated_reopen::reopen_store(
            db.file.path(),
            db.identity,
            authority(),
            guard(),
        )
        .unwrap();
        let effects = reopened.load_task_run_effects(task).unwrap();
        assert!(effects.cancellation_requested);
        assert!(effects.attempt_id.is_none());
        assert_eq!(
            effects.remote.outcome,
            runne_api::RemoteEffectOutcomeV1::NotStarted
        );
        assert_eq!(
            effects.remote.cancellation,
            runne_api::RemoteCancellationV1::NotRequested
        );
        assert_eq!(
            effects.remote.accounting,
            runne_api::RemoteAccountingV1::NotApplicable
        );
    }
}

#[test]
fn queued_cancellation_missing_or_changed_receipts_never_proves_no_effect() {
    for sequence in [1, 3, 4] {
        let (db, task) = completed("queued-effect-unproven", true, "");
        db.connection().execute("UPDATE command_receipts SET fingerprint=zeroblob(32) WHERE command_id=(SELECT command_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2)", rusqlite::params![task.as_bytes(), sequence]).unwrap();
        if let Ok(effects) = db.store.load_task_run_effects(task) {
            assert_eq!(
                effects.remote.outcome,
                runne_api::RemoteEffectOutcomeV1::Unknown
            );
            assert_eq!(
                effects.remote.cancellation,
                runne_api::RemoteCancellationV1::Unconfirmed
            );
        }
    }
}

#[test]
fn queued_cancellation_claim_evidence_keeps_remote_uncertain() {
    let (db, task) = completed("queued-effect-claim-evidence", true, "");
    db.connection()
        .execute(
            "INSERT INTO taskrun_fence_counters(taskrun_id,last_fence) VALUES(?1,1)",
            [task.as_bytes()],
        )
        .unwrap();
    if let Ok(effects) = db.store.load_task_run_effects(task) {
        assert_eq!(
            effects.remote.outcome,
            runne_api::RemoteEffectOutcomeV1::Unknown
        );
        assert_eq!(
            effects.remote.cancellation,
            runne_api::RemoteCancellationV1::Unconfirmed
        );
    }
}

#[test]
fn queued_runtime_actor_cancellation_proves_not_started() {
    let (db, task) = completed("queued-effect-runtime-completion", true, "runne-runtime");
    assert_eq!(
        db.store.load_task_run_effects(task).unwrap().remote.outcome,
        runne_api::RemoteEffectOutcomeV1::NotStarted
    );
}

#[test]
fn queued_runtime_principal_with_wrong_actor_stays_uncertain() {
    let (db, task) = completed(
        "queued-effect-wrong-runtime-actor",
        true,
        "different-worker",
    );
    let effects = db.store.load_task_run_effects(task).unwrap();
    assert_eq!(
        effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown
    );
    assert_eq!(
        effects.remote.cancellation,
        runne_api::RemoteCancellationV1::Unconfirmed
    );
}

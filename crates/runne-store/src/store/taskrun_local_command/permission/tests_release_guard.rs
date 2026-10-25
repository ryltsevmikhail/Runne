//! Synthetic area/callback only; real prepared target, root and durable admission.
#[path = "../../permission_modes/tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_binding_predicates.rs"]
mod binding_predicates;
#[path = "../../permission_modes/tests_capture_retention/ceremony.rs"]
mod ceremony;
#[path = "tests_cross_mode.rs"]
mod cross_mode;
#[path = "tests_cross_policy_data.rs"]
mod cross_policy_data;
#[path = "tests_expired_original.rs"]
mod expired_original;
#[path = "../../permission_modes/tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "tests_release_mode.rs"]
mod mode;
#[path = "tests_native_ordered.rs"]
mod native_ordered;
#[path = "tests_qualification_bindings.rs"]
mod qualification_bindings;
#[path = "tests_qualification_observations.rs"]
mod qualification_observations;
#[path = "tests_qualification_policy_data.rs"]
mod qualification_policy_data;
#[path = "tests_qualification_selection.rs"]
mod qualification_selection;
#[path = "tests_retained_cases.rs"]
mod retained_cases;
#[path = "tests_retained_data.rs"]
mod retained_data;
#[path = "tests_retained_support.rs"]
mod support;
#[path = "../../permission_modes/tests_capture_retention/target.rs"]
mod target;

use super::{burn_guard, owner::PermissionRootFenceRequestV1, release_guard};
use fixture::Fixture;
use runne_application::{permission_modes::PermissionMode, ports::EventStoreError};
use rusqlite::TransactionBehavior;

// Removing any pre-GO root check must fail the wrong-root control.
// Keeping the old revision-equality veto must fail the compatible-gap case.
fn run(reselect: bool, wrong_root: bool) {
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (b, captured, prepared) = target::capture(&f);
    let approval_id = approval::confirm(&f, &b);
    f.store
        .admit_local_command_permission(&b, Some(approval_id))
        .expect("genuine native admission before shared guard");
    let proof = approval::durable(&f, &b, approval_id);
    let owner = f.store.inner.permission_owner.as_ref().unwrap();
    let lease = owner
        .acquire_effect_lease(&f.store.runtime_authority_id, f.trust_id())
        .unwrap();
    // This byte sequence has no LinuxManagedArea or native child authority.
    let mut area = [1; 100];
    area[..4].copy_from_slice(b"RMA1");
    area[52..68].copy_from_slice(b.assignment().taskrun_id.as_bytes());
    area[68..84].copy_from_slice(b.assignment().attempt_id.as_bytes());
    let request = PermissionRootFenceRequestV1::new(
        f.scope.workspace_id,
        b.workspace_version(),
        b.admitted_root_version(),
        *b.held_root_identity_digest().as_bytes(),
    );
    {
        let mut writer = f.store.inner.writer.lock().unwrap();
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let root = owner
            .acquire_root_fence(&f.store.runtime_authority_id, &request)
            .unwrap();
        burn_guard::commit_in_tx(
            &tx,
            &f.store,
            b.assignment(),
            b.claim_stream_version(),
            &b,
            &area,
            captured.binding_digest,
            root.as_ref(),
            lease.as_ref(),
        )
        .expect("actual production burn tx");
        tx.commit().unwrap();
        drop(root);
    }
    if reselect {
        // Sequential SAME-lease fault/model schedule, not independent concurrency.
        mode::commit(&f, PermissionMode::RiskBased, 1, lease.as_ref());
    }
    assert_eq!(approval::durable(&f, &b, approval_id), proof);
    let unrelated = wrong_root.then(Fixture::new);
    let mut counter = 0;
    let result = {
        let mut writer = f.store.inner.writer.lock().unwrap();
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        // A second actual registered held-file root, not a mock guard.
        let root_fixture = unrelated.as_ref().unwrap_or(&f);
        let root_owner = root_fixture.store.inner.permission_owner.as_ref().unwrap();
        let root_identity = runne_platform::local_command_linux::LinuxCompositeScopeAdmission::workspace_root_identity(&root_fixture.held).unwrap();
        let release_request = PermissionRootFenceRequestV1::new(
            root_fixture.scope.workspace_id,
            2,
            2,
            *root_identity.as_bytes(),
        );
        let root = root_owner
            .acquire_root_fence(&root_fixture.store.runtime_authority_id, &release_request)
            .expect(
                "actual registered root acquisition must succeed, including unrelated-root control",
            );
        let observation = release_guard::ReleaseObservation::from_prepared(prepared.observation());
        let result = release_guard::with_release_preconditions(
            &tx,
            &f.store,
            b.assignment(),
            b.claim_stream_version(),
            &b,
            &area,
            captured.binding_digest,
            lease.as_ref(),
            root.as_ref(),
            &observation,
            || {
                counter += 1;
                Ok(())
            },
        );
        if result.is_ok() {
            tx.commit().unwrap();
        }
        drop(root);
        result
    };
    if wrong_root {
        assert_eq!(result, Err(EventStoreError::CorruptData));
        assert_eq!(counter, 0);
    } else {
        eprintln!("SHARED_MODEL_RELEASE reselect={reselect} result={result:?} counter={counter}");
        assert_eq!(
            result,
            Ok(()),
            "all shared production preconditions must permit the synthetic callback"
        );
        assert_eq!(counter, 1);
        let state: String = f
            .store
            .inner
            .reader
            .lock()
            .unwrap()
            .query_row(
                "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
                [b.assignment().taskrun_id.as_bytes()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "running");
    }
}

#[test]
fn original_current_shared_release_reaches_counter_once() {
    run(false, false);
}
#[test]
fn wrong_registered_root_never_reaches_counter() {
    run(false, true);
}
#[test]
fn same_mode_commit_between_burn_and_shared_release_retains_original() {
    run(true, false);
}

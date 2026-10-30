//! Genuine original Human admission; simulated area/callback, never native GO.
use super::super::{
    admission_checks, original_approval_facts::OriginalApprovalFacts, retained_policy,
    retained_policy_rows,
};
use super::{ceremony, mode, support::Case};
use runne_application::permission_modes::PermissionMode;

fn original_bytes(c: &Case) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    c.f.store
        .inner
        .reader
        .lock()
        .unwrap()
        .query_row(
            "SELECT b.retained_context,b.retained_context_digest,a.proof_digest,h.proof_digest
         FROM x2_permission_bindings b JOIN x2_permission_admission a USING(taskrun_id,attempt_id)
         JOIN x2_permission_human h USING(taskrun_id,attempt_id) WHERE b.taskrun_id=?1",
            [c.b.assignment().taskrun_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

// The old blanket mode veto must fail only after all immutable-original checks pass.
fn retains(original: PermissionMode, current: PermissionMode) {
    let c = Case::in_mode(true, original);
    let before =
        c.f.store
            .load_local_command_permission_capture(c.b.assignment().taskrun_id)
            .unwrap()
            .unwrap();
    let bytes = original_bytes(&c);
    assert_eq!(bytes.2, bytes.3);
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
    ceremony::commit(&c.f, current, 1); // Independent ModeFirst BEFORE outer lease.
    let after =
        c.f.store
            .load_local_command_permission_capture(c.b.assignment().taskrun_id)
            .unwrap()
            .unwrap();
    assert_eq!(after, before, "immutable original admitted capture");
    assert_eq!(
        original_bytes(&c),
        bytes,
        "original context and durable proof bytes"
    );
    ceremony::assert_same_policy(&c.f, &c.b);
    assert_eq!(
        c.prepared.observation().target_identity(),
        c.b.approval().target_identity_digest.as_bytes()
    );
    let reason =
        c.f.store
            .local_command_permission_stop_reason(c.b.assignment(), &c.b)
            .unwrap();
    eprintln!(
        "ORIGINAL_HUMAN_CROSS_MODE {original:?}->{current:?} unchanged_original=true stop={reason:?}"
    );
    assert_eq!(
        reason, None,
        "compatible original ADMITTED Human must survive a label-only transition"
    );
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert!(c.burn(lease.as_ref()).is_err(), "no second one-shot burn");
    assert_eq!(original_bytes(&c), bytes);
}

#[test]
fn risk_to_ask_retains_original_admitted_human() {
    retains(PermissionMode::RiskBased, PermissionMode::AskAlways);
}
#[test]
fn ask_to_risk_retains_original_admitted_human() {
    retains(PermissionMode::AskAlways, PermissionMode::RiskBased);
}

#[test]
fn same_lease_cross_mode_burn_gap_keeps_human_and_one_shot() {
    let c = Case::new(true);
    let bytes = original_bytes(&c);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    mode::commit(&c.f, PermissionMode::AskAlways, 1, lease.as_ref());
    assert_eq!(original_bytes(&c), bytes);
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert!(c.burn(lease.as_ref()).is_err());
    mode::commit_expiring(&c.f, PermissionMode::RiskBased, 2, lease.as_ref());
    assert_eq!(
        c.f.store
            .local_command_permission_stop_reason(c.b.assignment(), &c.b)
            .unwrap(),
        Some(2)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
}

#[test]
fn cross_mode_original_query_rejects_corrupt_facts_and_missing_admission() {
    let c = Case::new(true);
    ceremony::commit(&c.f, PermissionMode::AskAlways, 1);
    let mut writer = c.f.store.inner.writer.lock().unwrap();
    let tx = writer.transaction().unwrap();
    let (capture, context) = retained_policy_rows::load(&tx, c.b.assignment().taskrun_id).unwrap();
    let mut context = context.unwrap();
    let now = super::super::model::now_ms();
    assert!(
        admission_checks::classify_original_admission(
            &tx,
            &capture,
            &OriginalApprovalFacts::from_context(&context),
            now
        )
        .unwrap()
        .live_human(now)
    );
    // Corrupt original expected data is not a native token or a rewritten capture.
    context.approval.principal_id =
        runne_api::ApiPrincipalId::new("wrong-proof-principal").unwrap();
    assert!(
        admission_checks::classify_original_admission(
            &tx,
            &capture,
            &OriginalApprovalFacts::from_context(&context),
            now
        )
        .is_err()
    );
    drop(tx);
    drop(writer);
    let pending = Case::new(false);
    let mut writer = pending.f.store.inner.writer.lock().unwrap();
    let tx = writer.transaction().unwrap();
    let (mut capture, context) =
        retained_policy_rows::load(&tx, pending.b.assignment().taskrun_id).unwrap();
    let context = context.unwrap();
    let facts = OriginalApprovalFacts::from_context(&context);
    assert!(
        !admission_checks::classify_original_admission(&tx, &capture, &facts, now)
            .unwrap()
            .live_human(now)
    );
    // DATA claim of admitted state with no durable admission MUST NOT become Pending/Auto.
    capture.state = crate::store::LocalCommandAttemptState::Approved;
    assert!(admission_checks::classify_original_admission(&tx, &capture, &facts, now).is_err());
}

#[test]
fn cross_mode_terminal_selection_cas_and_monitor_share_verified_classifier() {
    let c = Case::new(true);
    let lease = c.lease();
    let preliminary = {
        let mut writer = c.f.store.inner.writer.lock().unwrap();
        let tx = writer.transaction().unwrap();
        retained_policy::assess_binding(&tx, &c.f.store, &c.b, lease.as_ref()).unwrap()
    };
    mode::commit(&c.f, PermissionMode::AskAlways, 1, lease.as_ref());
    {
        let mut writer = c.f.store.inner.writer.lock().unwrap();
        let tx = writer.transaction().unwrap();
        assert!(
            super::super::capture::verify_current_selection(
                &tx,
                &c.f.scope,
                &preliminary.selection,
                c.f.trust_id()
            )
            .is_err()
        );
        let current =
            retained_policy::assess_binding(&tx, &c.f.store, &c.b, lease.as_ref()).unwrap();
        assert_eq!(current.stop, None);
        assert_ne!(current.selection, preliminary.selection);
    }
    drop(lease);
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
}

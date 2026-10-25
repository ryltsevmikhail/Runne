//! Actual expired original proof with shared terminal DATA checks, not a child UoW.
use super::super::{
    admission_checks, model::now_ms, original_approval_facts::OriginalApprovalFacts,
    retained_policy, retained_policy_rows,
};
use super::{approval, ceremony, fixture::Fixture, target};
use runne_application::permission_modes::*;

#[test]
fn lifetime_expired_stopped_original_verifies_history_but_never_live_human() {
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (prepared_binding, prepared) = target::prepare(&f);
    let b = &prepared_binding;
    let mut approval = b.approval().clone();
    approval.expires_at_unix_ms = now_ms() + 3_000;
    // All native/compiler/assignment inputs originate in the actual preparation.
    // Shorten the ORIGINAL deadline before its first capture, never an issued grant.
    let binding = LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection: b.selection().clone(),
        assignment: b.assignment().clone(),
        claim_stream_version: b.claim_stream_version(),
        invocation_id: b.invocation_id(),
        project_id: b.project_id(),
        project_version: b.project_version(),
        workspace_version: b.workspace_version(),
        admitted_root_version: b.admitted_root_version(),
        held_root_identity_digest: b.held_root_identity_digest(),
        command: b.command().clone(),
        command_intent_digest: b.command_intent_digest(),
        approval,
        scope: b.scope().clone(),
        closed_rules_snapshot: b.closed_rules_snapshot(),
        closed_rules_digest: b.closed_rules_digest(),
        limits: b.limits(),
    })
    .unwrap();
    f.store
        .capture_local_command_permission(&binding, prepared.observation())
        .unwrap();
    let id = approval::confirm(&f, &binding);
    f.store
        .admit_local_command_permission(&binding, Some(id))
        .unwrap();
    let proof = approval::durable(&f, &binding, id);
    ceremony::commit(&f, PermissionMode::AskAlways, 1);
    assert_eq!(
        f.store
            .observe_local_command_permission_policy(&binding)
            .unwrap(),
        None
    );
    let remaining = binding.approval().expires_at_unix_ms - now_ms();
    if remaining > 0 {
        std::thread::sleep(std::time::Duration::from_millis(remaining as u64 + 5));
    }
    assert!(now_ms() >= binding.approval().expires_at_unix_ms);
    assert_eq!(
        f.store
            .observe_local_command_permission_policy(&binding)
            .unwrap(),
        Some(5)
    );
    f.store
        .record_local_command_permission_stop(binding.assignment(), &binding, 5)
        .unwrap();
    assert_eq!(approval::durable(&f, &binding, id), proof);
    let lease = f
        .store
        .observe_local_command_permission_trust(&binding)
        .unwrap();
    let mut writer = f.store.inner.writer.lock().unwrap();
    let tx = writer.transaction().unwrap();
    let (capture, original) =
        retained_policy_rows::load(&tx, binding.assignment().taskrun_id).unwrap();
    let original = original.unwrap();
    let facts = OriginalApprovalFacts::from_context(&original);
    let now = now_ms();
    let historical = admission_checks::verify_original_admission(
        &tx,
        &facts,
        &capture.binding_digest,
        now,
        true,
    )
    .unwrap();
    assert!(!historical.live_human(now));
    assert!(
        admission_checks::verify_original_admission(
            &tx,
            &facts,
            &capture.binding_digest,
            now,
            false
        )
        .is_err()
    );
    let preliminary =
        retained_policy::assess_binding(&tx, &f.store, &binding, lease.as_ref()).unwrap();
    assert_eq!(preliminary.stop, Some(5));
    super::super::capture::verify_current_selection(
        &tx,
        &f.scope,
        &preliminary.selection,
        f.trust_id(),
    )
    .unwrap();
    // Both terminal owners use this assessment; expired history remains inspectable.
    assert_eq!(
        retained_policy::assess_binding(&tx, &f.store, &binding, lease.as_ref())
            .unwrap()
            .stop,
        Some(5)
    );
    assert!(retained_policy::require_current(&tx, &f.store, &binding, lease.as_ref()).is_err());
    eprintln!("ACTUAL_EXPIRED_HUMAN historical_valid=true live=false stop=5 no_native_GO");
}

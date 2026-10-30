//! Real namespace readiness and durable admission; never releases a command.
#[path = "tests_admitted_retention/approval.rs"]
mod approval;
#[path = "tests_capture_retention/ceremony.rs"]
mod ceremony;
#[path = "tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "tests_capture_retention/target.rs"]
mod target;

#[path = "tests_admitted_retention/fresh_target.rs"]
mod fresh_target;

use fixture::Fixture;
use runne_application::permission_modes::PermissionMode;

#[test]
fn original_approved_binding_has_durable_native_admission() {
    let fixture = Fixture::new();
    ceremony::commit(&fixture, PermissionMode::RiskBased, 0);
    let (binding, captured, prepared) = target::capture(&fixture);
    let id = approval::confirm(&fixture, &binding);
    let receipt = fixture
        .store
        .admit_local_command_permission(&binding, Some(id))
        .unwrap_or_else(|error| panic!("ADMITTED_FIXTURE_GATE/NOTRUN: {error:?}"));
    assert_eq!(receipt.scope_digest(), binding.scope().digest().unwrap());
    assert_eq!(
        receipt.managed_policy_digest(),
        binding.approval().relevant_policy_digest
    );
    let mut expected = captured;
    expected.state = crate::store::LocalCommandAttemptState::Approved;
    let actual = fixture
        .store
        .load_local_command_permission_capture(binding.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(actual, expected);
    let proof = approval::durable(&fixture, &binding, id);
    assert_eq!(
        fixture
            .store
            .local_command_permission_stop_reason(binding.assignment(), &binding)
            .unwrap(),
        None
    );
    assert_eq!(
        prepared.observation().target_identity(),
        binding.approval().target_identity_digest.as_bytes()
    );
    eprintln!(
        "ADMITTED_BASELINE_QUALIFIED canonical={} capture={} proof={} native_handle={}",
        hex::encode(actual.canonical_binding_digest),
        hex::encode(actual.binding_digest),
        hex::encode(proof),
        hex::encode(receipt.platform_handle_id().as_bytes())
    );
}

// A blanket revision-only fanout invalidation must fail this genuine admitted case.
#[test]
fn same_mode_revision_preserves_original_admitted_human_proof() {
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (b, _, prepared) = target::capture(&f);
    let id = approval::confirm(&f, &b);
    f.store
        .admit_local_command_permission(&b, Some(id))
        .unwrap_or_else(|e| panic!("ADMITTED_FIXTURE_GATE/NOTRUN: {e:?}"));
    let before = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    let proof = approval::durable(&f, &b, id);
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(b.assignment(), &b)
            .unwrap(),
        None
    );
    ceremony::commit(&f, PermissionMode::RiskBased, 1);
    let selected = f
        .store
        .load_permission_mode_selection(&f.scope, &f.principal)
        .unwrap();
    assert_eq!(selected.authorization_revision, 2);
    assert_eq!(selected.selected_mode, b.selection().selected_mode);
    assert_eq!(selected.preset_version, b.selection().preset_version);
    assert_eq!(
        selected.expires_at_unix_ms,
        b.selection().expires_at_unix_ms
    );
    ceremony::assert_same_policy(&f, &b);
    let after = f
        .store
        .load_local_command_permission_capture(b.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after, before,
        "original admitted capture must not be rewritten"
    );
    assert_eq!(
        approval::durable(&f, &b, id),
        proof,
        "original human proof must remain byte-identical"
    );
    assert_eq!(
        prepared.observation().target_identity(),
        b.approval().target_identity_digest.as_bytes()
    );
    let reason = f
        .store
        .local_command_permission_stop_reason(b.assignment(), &b)
        .unwrap();
    eprintln!(
        "GENUINE_ADMITTED_RETENTION original={} proof={} revision=1->2 observed={reason:?} expected=None",
        hex::encode(before.canonical_binding_digest),
        hex::encode(proof)
    );
    assert_eq!(
        reason, None,
        "compatible same-mode revision must retain original ADMITTED human grant"
    );
}

// Removing exact original invocation verification must fail this safe refusal control.
#[test]
fn fresh_captured_invocation_requires_its_own_original_approval() {
    use crate::store::LocalCommandAttemptState;
    use runne_application::ports::EventStoreError;
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (old, _, old_target) = fresh_target::capture(&f);
    let old_id = approval::confirm(&f, &old);
    f.store
        .admit_local_command_permission(&old, Some(old_id))
        .unwrap_or_else(|e| panic!("ADMITTED_FIXTURE_GATE/NOTRUN original: {e:?}"));
    let old_proof = approval::durable(&f, &old, old_id);
    let (fresh, capture, fresh_target) = fresh_target::capture(&f);
    assert_ne!(old.assignment().taskrun_id, fresh.assignment().taskrun_id);
    assert_ne!(old.assignment().attempt_id, fresh.assignment().attempt_id);
    assert_ne!(old.invocation_id(), fresh.invocation_id());
    assert_ne!(old.approval().digest(), fresh.approval().digest());
    assert_eq!(old.assignment().node_epoch, fresh.assignment().node_epoch);
    assert_eq!(
        f.store.admit_local_command_permission(&fresh, Some(old_id)),
        Err(EventStoreError::CorruptData)
    );
    assert_eq!(
        f.store
            .load_local_command_permission_capture(fresh.assignment().taskrun_id)
            .unwrap()
            .unwrap(),
        capture
    );
    let rows: i64 = f
        .store
        .inner
        .reader
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM x2_permission_admission WHERE taskrun_id=?1",
            [fresh.assignment().taskrun_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "old approval must create no fresh admission");
    // Positive matching-approval control proves the preceding error was not bad setup.
    let fresh_id = approval::confirm(&f, &fresh);
    assert_ne!(old_id, fresh_id);
    f.store
        .admit_local_command_permission(&fresh, Some(fresh_id))
        .unwrap_or_else(|e| panic!("ADMITTED_FIXTURE_GATE/NOTRUN fresh positive: {e:?}"));
    let fresh_proof = approval::durable(&f, &fresh, fresh_id);
    assert_ne!(fresh_proof, old_proof);
    assert_eq!(approval::durable(&f, &old, old_id), old_proof);
    let mut expected = capture;
    expected.state = LocalCommandAttemptState::Approved;
    assert_eq!(
        f.store
            .load_local_command_permission_capture(fresh.assignment().taskrun_id)
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(old.assignment(), &old)
            .unwrap(),
        None
    );
    assert_eq!(
        f.store
            .local_command_permission_stop_reason(fresh.assignment(), &fresh)
            .unwrap(),
        None
    );
    assert_eq!(
        old_target.observation().owner_id(),
        fresh_target.observation().owner_id()
    );
    eprintln!(
        "FRESH_INVOCATION_CONTROL_QUALIFIED old={} fresh={} old_proof={} fresh_proof={}",
        old.invocation_id(),
        fresh.invocation_id(),
        hex::encode(old_proof),
        hex::encode(fresh_proof)
    );
}

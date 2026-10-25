//! Original evidence persistence only; no admission, burn or GO.
#[path = "tests_capture_retention/fixture.rs"]
mod fixture;
#[path = "tests_capture_retention/target.rs"]
mod target;

#[test]
fn checked_original_context_preserves_full_original_binding_data() {
    let fixture = fixture::Fixture::new();
    let (binding, capture, _prepared) = target::capture(&fixture);
    let context = crate::store::taskrun_local_command::permission::retained_context::from_capture(
        &binding,
        &capture.binding,
        capture.binding_digest,
    );
    assert!(
        context.is_ok(),
        "valid original capture data must reconstruct original context: {context:?}"
    );
}

#[test]
fn current_capture_persists_original_context_pair() {
    let fixture = fixture::Fixture::new();
    let (binding, capture, _prepared) = target::capture(&fixture);
    let _ = &fixture.launch;
    let writer = fixture.store.inner.writer.lock().unwrap();
    let pair: (Option<Vec<u8>>, Option<Vec<u8>>) = writer.query_row(
        "SELECT retained_context,retained_context_digest FROM x2_permission_bindings WHERE taskrun_id=?1",
        [binding.assignment().taskrun_id.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert!(
        pair.0.is_some() && pair.1.is_some(),
        "every new valid capture must retain both original context fields"
    );
    let context = pair.0.unwrap();
    assert_eq!(&context[..3], &[0, 1, 1], "binary context1 and capture1");
    assert_eq!(pair.1.unwrap().len(), 32);
    assert_eq!(
        capture.canonical_binding_digest,
        *binding.digest().as_bytes()
    );
    crate::schema::apply_migrations(&writer).unwrap();
    assert!(
        writer
            .execute(
                "UPDATE x2_permission_bindings SET retained_context=NULL",
                []
            )
            .is_err()
    );
    assert!(
        writer
            .execute("DELETE FROM x2_permission_bindings", [])
            .is_err()
    );
}

fn unsupported(
    original: &runne_application::permission_modes::LocalCommandPermissionBindingV1,
) -> runne_application::permission_modes::LocalCommandPermissionBindingV1 {
    use runne_application::permission_modes::*;
    let mut scope = original.scope().clone();
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    scope.filesystem.posture = FilesystemPosture::None;
    scope.children = ChildDelegationScope::MaxDepth(0);
    scope.budget = EffectBudget {
        max_operations: Some(0),
        max_bytes: Some(u64::MAX),
    };
    let mut approval = original.approval().clone();
    approval.composite_scope_digest = scope.digest().unwrap();
    approval.containment_version = scope.containment;
    LocalCommandPermissionBindingV1::checked(LocalCommandPermissionBindingInputV1 {
        selection: original.selection().clone(),
        assignment: original.assignment().clone(),
        claim_stream_version: original.claim_stream_version(),
        invocation_id: original.invocation_id(),
        project_id: original.project_id(),
        project_version: original.project_version(),
        workspace_version: original.workspace_version(),
        admitted_root_version: original.admitted_root_version(),
        held_root_identity_digest: original.held_root_identity_digest(),
        command: original.command().clone(),
        command_intent_digest: original.command_intent_digest(),
        approval,
        scope,
        closed_rules_snapshot: original.closed_rules_snapshot(),
        closed_rules_digest: original.closed_rules_digest(),
        limits: original.limits(),
    })
    .unwrap()
}

#[test]
fn valid_unsupported_capture_remains_nonnull_and_ready_without_admission() {
    let fixture = fixture::Fixture::new();
    let (original, prepared) = target::prepare(&fixture);
    let binding = unsupported(&original);
    fixture
        .store
        .capture_local_command_permission(&binding, prepared.observation())
        .unwrap();
    let writer = fixture.store.inner.writer.lock().unwrap();
    let bytes: Vec<u8> = writer
        .query_row(
            "SELECT retained_context FROM x2_permission_bindings",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        &bytes[bytes.len() - 4..],
        &[0, 1, 0, 1],
        "valid Unsupported projection"
    );
    crate::schema::apply_migrations(&writer).unwrap();
}

#[test]
fn rehashed_corrupt_context_is_rejected_by_schema_readiness() {
    let fixture = fixture::Fixture::new();
    let (_, _, _prepared) = target::capture(&fixture);
    let writer = fixture.store.inner.writer.lock().unwrap();
    crate::schema::apply_migrations(&writer).unwrap();
    let mut bytes: Vec<u8> = writer
        .query_row(
            "SELECT retained_context FROM x2_permission_bindings",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let hash =
        crate::store::taskrun_local_command::permission::retained_context_codec::context_digest(
            &bytes,
        )
        .unwrap();
    // Explicit corruption of a new owned fixture, never legitimate authority evidence.
    writer
        .execute_batch("DROP TRIGGER x2_permission_bindings_immutable")
        .unwrap();
    writer
        .execute(
            "UPDATE x2_permission_bindings SET retained_context=?1,retained_context_digest=?2",
            rusqlite::params![bytes, hash],
        )
        .unwrap();
    writer.execute_batch("CREATE TRIGGER x2_permission_bindings_immutable BEFORE UPDATE ON x2_permission_bindings BEGIN SELECT RAISE(ABORT,'X2 permission binding is immutable'); END").unwrap();
    assert!(crate::schema::apply_migrations(&writer).is_err());
}

#[test]
fn legacy_null_context_is_readiness_absence_not_current_policy_backfill() {
    use crate::store::{PermissionModeSelectionSnapshot, taskrun_local_command::permission::codec};
    let fixture = fixture::Fixture::new();
    let (binding, prepared) = target::prepare(&fixture);
    let observation = prepared.observation();
    let record = codec::CaptureV1::from_binding(
        &binding,
        *observation.owner_id(),
        observation.owner_generation(),
        &PermissionModeSelectionSnapshot {
            selection: binding.selection().clone(),
            managed_policy_version: binding.closed_rules_snapshot().record.revision,
            managed_policy_digest: binding.closed_rules_digest(),
        },
    )
    .unwrap();
    let bytes = codec::encode(&record).unwrap();
    let digest = codec::binding_digest(&bytes).unwrap();
    let writer = fixture.store.inner.writer.lock().unwrap();
    // A legacy-shaped, data-only row under all intact production INSERT guards.
    writer.execute("INSERT INTO x2_permission_bindings(taskrun_id,attempt_id,fence,invocation_id,binding_digest,codec_version,binding,native_owner_id,native_owner_generation,selection_managed_policy_version,selection_managed_policy_digest,captured_at) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?9,?10,1)",
        rusqlite::params![record.taskrun_id,record.attempt_id,i64::try_from(record.fence).unwrap(),record.invocation_id,digest,bytes,record.native_owner_id,record.native_owner_generation.to_be_bytes(),i64::try_from(record.selection_managed_policy_version).unwrap(),record.selection_managed_policy_digest]).unwrap();
    crate::schema::apply_migrations(&writer).unwrap();
    let pair: (Option<Vec<u8>>, Option<Vec<u8>>) = writer
        .query_row(
            "SELECT retained_context,retained_context_digest FROM x2_permission_bindings",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(pair, (None, None));
}

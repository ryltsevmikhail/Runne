use gocode_local_store::{
    BoundedCanonicalId, MutationIdentity, MutationOperation, MutationTargetKind,
};

#[test]
fn mutation_ledger_rejects_a_target_outside_its_closed_operation_matrix() {
    let target = id();
    assert!(
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::WorkspaceOpen,
            MutationTargetKind::Project,
            target,
            "idem-1",
            0,
            [3; 32],
        )
        .is_err()
    );
}

#[test]
fn mutation_ledger_rejects_unbounded_or_control_idempotency_keys() {
    let target = id();
    for key in [
        String::new(),
        "x".repeat(257),
        "key\0".into(),
        "key\u{1f}".into(),
        "key\u{7f}".into(),
    ] {
        assert!(
            MutationIdentity::new(
                [1; 32],
                [2; 32],
                MutationOperation::ProjectCreate,
                MutationTargetKind::Project,
                target.clone(),
                key,
                0,
                [3; 32],
            )
            .is_err()
        );
    }
}

#[test]
fn mutation_ledger_accepts_a_maximum_safe_idempotency_key() {
    let target = id();
    assert!(
        MutationIdentity::new(
            [1; 32],
            [2; 32],
            MutationOperation::ProjectCreate,
            MutationTargetKind::Project,
            target,
            "x".repeat(256),
            0,
            [3; 32],
        )
        .is_ok()
    );
}

fn id() -> BoundedCanonicalId {
    BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000001").unwrap()
}

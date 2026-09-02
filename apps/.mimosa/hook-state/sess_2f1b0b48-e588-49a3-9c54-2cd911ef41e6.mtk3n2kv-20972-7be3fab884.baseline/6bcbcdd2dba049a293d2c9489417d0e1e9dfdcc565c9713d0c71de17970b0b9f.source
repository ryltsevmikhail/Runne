use std::time::{Duration, UNIX_EPOCH};

use runne_app_core::{
    ApprovalConfirmationBinding, ApprovalConfirmationParts, ApprovalDecisionBinding,
    ApprovalDecisionDto, CanonicalId, MutationAdmissionBinding,
};

use super::ApprovalIntentManager;

fn id(value: &str) -> CanonicalId {
    CanonicalId::parse(value).expect("canonical ID")
}

fn admission() -> MutationAdmissionBinding {
    MutationAdmissionBinding {
        runtime_identity_digest: [1; 32],
        principal_digest: [2; 32],
        gate_epoch: 3,
    }
}

fn parts() -> ApprovalConfirmationParts {
    ApprovalConfirmationParts {
        approval_id: id("018f2e3a-7000-7000-8000-000000000212"),
        task_run_id: id("018f2e3a-7000-7000-8000-000000000213"),
        attempt_id: Some(id("018f2e3a-7000-7000-8000-000000000214")),
        invocation_id: id("018f2e3a-7000-7000-8000-000000000215"),
        action: "fs:write".to_owned(),
        resource: "workspace:/src/main.rs".to_owned(),
        action_digest: [4; 32],
        policy_revision: 7,
        expires_at: 1_800_000_005_000,
    }
}

fn binding_with(
    admission: MutationAdmissionBinding,
    parts: ApprovalConfirmationParts,
) -> ApprovalConfirmationBinding {
    ApprovalConfirmationBinding::new(
        admission,
        parts,
        ApprovalDecisionBinding {
            expected_version: 1,
            decision: ApprovalDecisionDto::Approve,
        },
    )
    .expect("binding")
}

fn identity_substitutions(
    baseline_admission: MutationAdmissionBinding,
    baseline_parts: &ApprovalConfirmationParts,
) -> Vec<ApprovalConfirmationBinding> {
    vec![
        binding_with(
            MutationAdmissionBinding {
                runtime_identity_digest: [8; 32],
                ..baseline_admission
            },
            baseline_parts.clone(),
        ),
        binding_with(
            MutationAdmissionBinding {
                principal_digest: [8; 32],
                ..baseline_admission
            },
            baseline_parts.clone(),
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                approval_id: id("018f2e3a-7000-7000-8000-000000000216"),
                ..baseline_parts.clone()
            },
        ),
    ]
}

fn approval_substitutions(
    baseline_admission: MutationAdmissionBinding,
    baseline_parts: &ApprovalConfirmationParts,
) -> Vec<ApprovalConfirmationBinding> {
    vec![
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                expires_at: 1_800_000_004_999,
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            MutationAdmissionBinding {
                gate_epoch: 4,
                ..baseline_admission
            },
            baseline_parts.clone(),
        ),
        ApprovalConfirmationBinding::new(
            baseline_admission,
            baseline_parts.clone(),
            ApprovalDecisionBinding {
                expected_version: 2,
                decision: ApprovalDecisionDto::Approve,
            },
        )
        .expect("version binding"),
        ApprovalConfirmationBinding::new(
            baseline_admission,
            baseline_parts.clone(),
            ApprovalDecisionBinding {
                expected_version: 1,
                decision: ApprovalDecisionDto::Deny,
            },
        )
        .expect("decision binding"),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                task_run_id: id("018f2e3a-7000-7000-8000-000000000216"),
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                attempt_id: None,
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                invocation_id: id("018f2e3a-7000-7000-8000-000000000216"),
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                resource: "workspace:/other.rs".to_owned(),
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                action: "fs:delete".to_owned(),
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                action_digest: [8; 32],
                ..baseline_parts.clone()
            },
        ),
        binding_with(
            baseline_admission,
            ApprovalConfirmationParts {
                policy_revision: 8,
                ..baseline_parts.clone()
            },
        ),
    ]
}

fn substituted_bindings(
    admission: MutationAdmissionBinding,
    parts: &ApprovalConfirmationParts,
) -> Vec<ApprovalConfirmationBinding> {
    let mut values = identity_substitutions(admission, parts);
    values.extend(approval_substitutions(admission, parts));
    values
}

#[test]
fn approval_intent_requires_absolute_and_monotonic_deadlines() {
    let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let wall = UNIX_EPOCH + Duration::from_hours(500_000);
    let monotonic = std::time::Instant::now();
    let value = binding_with(admission(), parts());
    let intent = manager
        .prepare_with_clock("main", 9, value.clone(), wall, monotonic)
        .expect("prepare");
    assert!(
        manager
            .consume_with_clock(
                &intent,
                "main",
                9,
                &value,
                wall - Duration::from_secs(1),
                monotonic + Duration::from_secs(31),
            )
            .is_err()
    );
}

#[test]
fn approval_intent_uses_five_second_absolute_expiry_under_wall_clock_rollback() {
    let wall = UNIX_EPOCH + Duration::from_hours(500_000);
    let monotonic = std::time::Instant::now();
    let value = binding_with(admission(), parts());
    let valid_manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let valid = valid_manager
        .prepare_with_clock("main", 9, value.clone(), wall, monotonic)
        .expect("prepare valid");
    assert!(
        valid_manager
            .consume_with_clock(
                &valid,
                "main",
                9,
                &value,
                wall - Duration::from_secs(1),
                monotonic + Duration::from_millis(4_999),
            )
            .is_ok()
    );

    let expired_manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let expired = expired_manager
        .prepare_with_clock("main", 9, value.clone(), wall, monotonic)
        .expect("prepare expiry");
    assert!(
        expired_manager
            .consume_with_clock(
                &expired,
                "main",
                9,
                &value,
                wall - Duration::from_secs(1),
                monotonic + Duration::from_secs(5),
            )
            .is_err()
    );
}

#[test]
fn approval_intent_rejects_replay_expiry_and_every_tuple_substitution() {
    let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let now = UNIX_EPOCH + Duration::from_hours(500_000);
    let baseline_admission = admission();
    let baseline_parts = parts();
    let value = binding_with(baseline_admission, baseline_parts.clone());
    let intent = manager
        .prepare("main", 9, value.clone(), now)
        .expect("prepare");
    assert!(manager.consume(&intent, "main", 9, &value, now).is_ok());
    assert!(manager.consume(&intent, "main", 9, &value, now).is_err());

    let expired = UNIX_EPOCH + Duration::from_millis(1_800_000_005_001);
    let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let intent = manager
        .prepare("main", 9, value.clone(), now)
        .expect("prepare again");
    assert!(
        manager
            .consume(&intent, "main", 9, &value, expired)
            .is_err()
    );

    for changed in substituted_bindings(baseline_admission, &baseline_parts) {
        let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
        let intent = manager
            .prepare("main", 9, value.clone(), now)
            .expect("prepare tuple");
        assert!(manager.consume(&intent, "main", 9, &changed, now).is_err());
    }
    let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let intent = manager
        .prepare("main", 9, value.clone(), now)
        .expect("prepare window");
    assert!(manager.consume(&intent, "other", 9, &value, now).is_err());
    let manager = ApprovalIntentManager::new(Duration::from_secs(30)).expect("manager");
    let intent = manager
        .prepare("main", 9, value.clone(), now)
        .expect("prepare generation");
    assert!(manager.consume(&intent, "main", 10, &value, now).is_err());
}

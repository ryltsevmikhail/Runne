use runne_app_core::{
    ApprovalConfirmationBinding, ApprovalConfirmationParts, ApprovalDecisionBinding,
    ApprovalDecisionDto, CanonicalId, MutationAdmissionBinding,
};

use super::{approval_dialog_spec, dialog_result, parse_approval_decision};

fn binding(decision: ApprovalDecisionDto) -> ApprovalConfirmationBinding {
    ApprovalConfirmationBinding::new(
        MutationAdmissionBinding {
            runtime_identity_digest: [1; 32],
            principal_digest: [2; 32],
            gate_epoch: 3,
        },
        ApprovalConfirmationParts {
            approval_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000212").unwrap(),
            task_run_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000213").unwrap(),
            attempt_id: None,
            invocation_id: CanonicalId::parse("018f2e3a-7000-7000-8000-000000000214").unwrap(),
            action: "fs:write".into(),
            resource: "workspace:/src/main.rs".into(),
            action_digest: [4; 32],
            policy_revision: 7,
            approval_generation: 3,
            expires_at: 1_900_000_000,
        },
        ApprovalDecisionBinding {
            expected_version: 1,
            decision,
        },
    )
    .unwrap()
}

#[test]
fn approval_dialog_specs_are_decision_specific_and_fail_closed() {
    let approve = approval_dialog_spec(&binding(ApprovalDecisionDto::Approve));
    let deny = approval_dialog_spec(&binding(ApprovalDecisionDto::Deny));
    assert_ne!(approve.title, deny.title);
    assert_ne!(approve.message, deny.message);
    assert_ne!(approve.confirm_label, deny.confirm_label);
    assert!(!dialog_result(Ok(false)));
    assert!(!dialog_result(Err(())));
}

#[test]
fn approval_decision_parser_accepts_only_published_values() {
    assert_eq!(
        parse_approval_decision("approve").ok(),
        Some(ApprovalDecisionDto::Approve)
    );
    assert_eq!(
        parse_approval_decision("deny").ok(),
        Some(ApprovalDecisionDto::Deny)
    );
    assert!(parse_approval_decision("approved").is_err());
    assert!(parse_approval_decision("approve\n").is_err());
}

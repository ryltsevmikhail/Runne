use super::super::authorization::{
    AuthorizationReplayGuard, approval_scope, approve, issue_capability, validate_authorization,
};
use super::super::context::current_context;
use super::super::intent::{EnvironmentClassificationV1, ProcessEnvironmentGrantV1};
use super::super::{
    BoundedArgvV1, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, ProcessContractError,
    StdinPolicyV1,
};
use super::support::{approver, baseline, capability};

fn text(value: &str) -> PortableUtf8V1 {
    PortableUtf8V1::from_bytes(value.as_bytes().to_vec()).unwrap()
}

fn assert_redacted(value: impl core::fmt::Debug, marker: &str) {
    assert!(!format!("{value:?}").contains(marker));
}

#[test]
fn debug_and_errors_do_not_disclose_raw_process_input() {
    let marker = "distinct-process-secret";
    let bounds = InputBoundsV1::new(2, 64, 128).unwrap();
    let portable = text(marker);
    let argv = BoundedArgvV1::new(vec![portable.clone()], bounds).unwrap();
    let grant = ProcessEnvironmentGrantV1::exact(
        vec![(
            text("PROCESS_SECRET"),
            portable.clone(),
            EnvironmentClassificationV1::NonSecret,
        )],
        bounds,
    )
    .unwrap();
    let environment = ExplicitEnvironmentV1::from_exact_grant(
        &grant,
        vec![(text("PROCESS_SECRET"), portable.clone())],
        bounds,
    )
    .unwrap();
    let intent = baseline();
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let authority = approver(20);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let approval = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    let witness = validate_authorization(
        intent,
        Some(&capability),
        Some(&approval),
        &current,
        &mut replay_guard,
        1,
    )
    .unwrap();

    assert_redacted(portable, marker);
    assert_redacted(argv, marker);
    assert_redacted(grant, marker);
    assert_redacted(environment, marker);
    assert_redacted(StdinPolicyV1::closed(), marker);
    assert_redacted(witness.intent(), "tool");
    assert_redacted(capability, "tool");
    assert_redacted(approval, "tool");
    assert_redacted(witness, "tool");
    assert_eq!(
        ProcessContractError::ExecutableVerificationFailed.to_string(),
        "process executable verification failed"
    );
    assert_eq!(
        ProcessContractError::CwdVerificationFailed.to_string(),
        "process working directory verification failed"
    );
    for error in [
        ProcessContractError::IntentMalformed,
        ProcessContractError::InputBoundsExceeded,
        ProcessContractError::EnvironmentNotGranted,
        ProcessContractError::EnvironmentDenied,
        ProcessContractError::DigestEncodingInvalid,
        ProcessContractError::CapabilityInvalid,
        ProcessContractError::ExecutableVerificationFailed,
        ProcessContractError::CwdVerificationFailed,
        ProcessContractError::ApprovalInvalid,
    ] {
        assert!(!error.to_string().contains(marker));
        assert_redacted(error, marker);
    }
}

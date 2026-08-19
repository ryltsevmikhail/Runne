use runne_platform_ports::process::{
    HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessGenerationIdV1, ProcessOwnerIdV1,
    ProcessSessionIdV1,
};

use super::super::digest::{TlvEncoder, digest_intent};
use super::super::intent::{EnvironmentClassificationV1, ProcessEnvironmentGrantV1};
use super::super::{
    AllowedRootId, ApprovalId, AuthorityId, BoundedArgvV1, CapabilityGrantId, ExecutablePolicyId,
    ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessContractError,
    ProcessIdentityBindingV1, ProcessIntentV1, ProcessIoBoundsV1, SandboxId, StdinPolicyV1,
};
use super::support::{baseline, cwd_with_content, executable, id};

#[test]
fn canonical_encoder_rejects_duplicate_out_of_order_and_oversized_fields() {
    let mut encoder = TlvEncoder::default();
    encoder.field(2, b"first").unwrap();
    assert_eq!(
        encoder.field(2, b"duplicate"),
        Err(ProcessContractError::DigestEncodingInvalid)
    );
    assert_eq!(
        encoder.field(1, b"out-of-order"),
        Err(ProcessContractError::DigestEncodingInvalid)
    );
    assert_eq!(
        TlvEncoder::checked_u32_len(usize::MAX),
        Err(ProcessContractError::DigestEncodingInvalid)
    );
}

#[test]
fn canonical_digest_is_result_and_has_a_fixed_golden_vector() {
    let intent = baseline();
    let digest = digest_intent(&intent).unwrap();
    assert_eq!(
        hex::encode(digest.as_bytes()),
        "d41c83a26a4de135e8bf7623154cfff72f4d0eab8c44f69090a0fcb16606b448"
    );
}

fn text(value: &str) -> PortableUtf8V1 {
    PortableUtf8V1::from_bytes(value.as_bytes().to_vec()).unwrap()
}

fn binding(parts: [u8; 9]) -> ProcessIdentityBindingV1 {
    ProcessIdentityBindingV1::new(
        PrincipalId::new(id(parts[0])).unwrap(),
        AuthorityId::new(id(parts[1])).unwrap(),
        ProcessOwnerIdV1::new(id(parts[2])).unwrap(),
        ProcessAttemptIdV1::new(id(parts[3])).unwrap(),
        ProcessSessionIdV1::new(id(parts[4])).unwrap(),
        ProcessGenerationIdV1::new(id(parts[5])).unwrap(),
        CapabilityGrantId::new(id(parts[6])).unwrap(),
        SandboxId::new(id(parts[7])).unwrap(),
        HeldProcessTreeHandleV1::new(id(parts[8])).unwrap(),
    )
}

fn environment(reverse: bool, mutation: Option<&str>) -> ExplicitEnvironmentV1 {
    let mut values = vec![("ALPHA", "one"), ("BETA", "two")];
    if mutation == Some("environment_alpha") {
        values[0].1 = "changed";
    }
    if mutation == Some("environment_beta") {
        values[1].1 = "changed";
    }
    if reverse {
        values.reverse();
    }
    let bounds = InputBoundsV1::new(4, 16, 64).unwrap();
    let grant = ProcessEnvironmentGrantV1::exact(
        values
            .iter()
            .map(|(name, value)| {
                (
                    text(name),
                    text(value),
                    EnvironmentClassificationV1::NonSecret,
                )
            })
            .collect(),
        bounds,
    )
    .unwrap();
    ExplicitEnvironmentV1::from_exact_grant(
        &grant,
        values
            .into_iter()
            .map(|(name, value)| (text(name), text(value)))
            .collect(),
        bounds,
    )
    .unwrap()
}

fn synthetic(mutation: Option<&str>, reverse_environment: bool) -> ProcessIntentV1 {
    let mut executable_parts = [1, 2, 3, 4, 1];
    let mut cwd_parts = [5, 6, 12, 7, 1];
    let mut binding_parts = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut approval = 10;
    let mut policy = 11;
    let mut root = 12;
    let mut argv = vec!["tool", "flag"];
    let mut bounds = [5, 5, 8, 1];
    let mut cancel = true;
    match mutation {
        Some("approval") => approval = 13,
        Some("executable_token") => executable_parts[0] = 13,
        Some("executable_canonical") => executable_parts[1] = 13,
        Some("executable_content") => executable_parts[2] = 13,
        Some("executable_filesystem") => executable_parts[3] = 13,
        Some("executable_version") => executable_parts[4] = 2,
        Some("policy") => policy = 13,
        Some("cwd_token") => cwd_parts[0] = 13,
        Some("cwd_canonical") => cwd_parts[1] = 13,
        Some("cwd_content") => cwd_parts[2] = 13,
        Some("cwd_filesystem") => cwd_parts[3] = 13,
        Some("cwd_version") => cwd_parts[4] = 2,
        Some("root") => root = 13,
        Some("argv_first") => argv[0] = "tools",
        Some("argv_second") => argv[1] = "flags",
        Some("stdout") => bounds[0] = 3,
        Some("stderr") => bounds[1] = 3,
        Some("combined") => bounds[2] = 9,
        Some("timeout") => bounds[3] = 2,
        Some("cancel") => cancel = false,
        Some(field) if field.starts_with("binding_") => {
            let index = [
                "binding_principal",
                "binding_authority",
                "binding_owner",
                "binding_attempt",
                "binding_session",
                "binding_generation",
                "binding_accounting",
                "binding_sandbox",
                "binding_tree",
            ]
            .iter()
            .position(|name| *name == field)
            .unwrap();
            binding_parts[index] = 13;
        }
        _ => {}
    }
    ProcessIntentV1::new(
        ApprovalId::new(id(approval)).unwrap(),
        executable(
            executable_parts[0],
            executable_parts[1],
            executable_parts[2],
            executable_parts[3],
            u64::from(executable_parts[4]),
        ),
        ExecutablePolicyId::new(id(policy)).unwrap(),
        cwd_with_content(
            cwd_parts[0],
            cwd_parts[1],
            cwd_parts[2],
            cwd_parts[3],
            u64::from(cwd_parts[4]),
        ),
        AllowedRootId::new(id(root)).unwrap(),
        BoundedArgvV1::new(
            argv.into_iter().map(text).collect(),
            InputBoundsV1::new(4, 16, 64).unwrap(),
        )
        .unwrap(),
        environment(reverse_environment, mutation),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(bounds[0], bounds[1], bounds[2], bounds[3], cancel).unwrap(),
        binding(binding_parts),
    )
    .unwrap()
}

#[test]
fn canonical_digest_is_stable_for_environment_insertion_order() {
    assert_eq!(
        synthetic(None, false).digest(),
        synthetic(None, true).digest()
    );
}

#[test]
fn every_effect_changing_field_changes_the_digest() {
    let baseline = synthetic(None, false).digest();
    for field in [
        "approval",
        "executable_token",
        "executable_canonical",
        "executable_content",
        "executable_filesystem",
        "executable_version",
        "policy",
        "cwd_token",
        "cwd_canonical",
        "cwd_content",
        "cwd_filesystem",
        "cwd_version",
        "root",
        "argv_first",
        "argv_second",
        "environment_alpha",
        "environment_beta",
        "stdout",
        "stderr",
        "combined",
        "timeout",
        "cancel",
        "binding_principal",
        "binding_authority",
        "binding_owner",
        "binding_attempt",
        "binding_session",
        "binding_generation",
        "binding_accounting",
        "binding_sandbox",
        "binding_tree",
    ] {
        assert_ne!(baseline, synthetic(Some(field), false).digest(), "{field}");
    }
}

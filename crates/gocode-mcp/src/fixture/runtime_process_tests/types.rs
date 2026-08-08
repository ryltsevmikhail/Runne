use super::super::process_call::{
    ProcessEffectKey, audit_capability_digest, audit_connection_digest, audit_invocation_digest,
    process_effect_key_digest, process_permit_digest,
};

const PLANNED_CASES: [&str; 8] = [
    "planned_case_registry_has_exact_cardinality",
    "process_effect_key_digest_matches_golden_vector",
    "audit_invocation_digest_matches_golden_vector",
    "audit_connection_digest_matches_golden_vector",
    "audit_capability_digest_matches_golden_vector",
    "process_permit_digest_matches_golden_vector",
    "identical_inputs_are_domain_separated",
    "every_process_effect_key_field_changes_the_digest",
];

fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key() -> ProcessEffectKey {
    ProcessEffectKey::new(
        [1; 32],
        [2; 32],
        [3; 32],
        "invocation-1".into(),
        [4; 32],
        [5; 32],
        "connection-1".into(),
        7,
        "process".into(),
        [6; 32],
    )
}

#[test]
fn planned_case_registry_has_exact_cardinality() {
    assert_eq!(PLANNED_CASES.len(), 8);
}

#[test]
fn process_effect_key_digest_matches_golden_vector() {
    assert_eq!(
        hex(process_effect_key_digest(&key())),
        "06498fe052cabf73f163587e01b781e8bf16b342366cf6e461a102d8f270b429"
    );
}

#[test]
fn audit_invocation_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_invocation_digest("invocation-1")),
        "bb89083d660719ed55da64d2342882f77c1821a35e7748ab119027b4007beb3f"
    );
}

#[test]
fn audit_connection_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_connection_digest("connection-1")),
        "4d2af0292273fcc4fbff40a4130912643b06f7c2bdecbc195c29bcfd0ce4ae3e"
    );
}

#[test]
fn audit_capability_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_capability_digest(&[7; 16])),
        "45e6e168dea7e0d412eda18163aaa6204fffc48188e7c074f9fb193a71b3b084"
    );
}

#[test]
fn process_permit_digest_matches_golden_vector() {
    assert_eq!(
        hex(process_permit_digest(
            process_effect_key_digest(&key()),
            &[7; 16],
            [6; 32]
        )),
        "61cd44dce5e93f3031ba5886554770fd884bacbb7b2405772a5d4d86264babe2"
    );
}

#[test]
fn identical_inputs_are_domain_separated() {
    let input = b"same";
    assert_ne!(
        audit_invocation_digest("same"),
        audit_connection_digest("same")
    );
    assert_ne!(
        audit_capability_digest(input),
        process_permit_digest([9; 32], input, [8; 32])
    );
}

#[test]
fn every_process_effect_key_field_changes_the_digest() {
    let original = process_effect_key_digest(&key());
    let variants = [
        ProcessEffectKey::new(
            [9; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [9; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [9; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-2".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [9; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [9; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-2".into(),
            7,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            8,
            "process".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "other".into(),
            [6; 32],
        ),
        ProcessEffectKey::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "invocation-1".into(),
            [4; 32],
            [5; 32],
            "connection-1".into(),
            7,
            "process".into(),
            [9; 32],
        ),
    ];
    assert!(
        variants
            .iter()
            .all(|candidate| process_effect_key_digest(candidate) != original)
    );
}

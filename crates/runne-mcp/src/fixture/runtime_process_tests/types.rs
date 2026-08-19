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
        "13dcc181de7e9339f5befe031797f89b973d8b52e14a0c6317293f911e0d4942"
    );
}

#[test]
fn audit_invocation_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_invocation_digest("invocation-1")),
        "d1645f5148f8f38e8bb907d1d869ed6efe90d5f362a0ed4e90d54acbf2ff186f"
    );
}

#[test]
fn audit_connection_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_connection_digest("connection-1")),
        "7e8b776a07b658ff669b9f7ec099f9d10abd4ac020cdac2c29feb7b98620e860"
    );
}

#[test]
fn audit_capability_digest_matches_golden_vector() {
    assert_eq!(
        hex(audit_capability_digest(&[7; 16])),
        "1b2b751ff413ff75feef4ca850251e0442b49d9d9c15ec49692ff9231f79fb93"
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
        "9bef3f0ff4ea2a457c987502a054e449ab1fb1e9dbd6c3e29e8775a843e1730f"
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

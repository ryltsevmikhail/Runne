use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

#[test]
fn context_and_fault_authorities_must_differ_by_key_and_key_id() {
    let context_key = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let fault_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let context_id = Sha256::digest(context_key.as_bytes()).into();
    let fault_id = Sha256::digest(fault_key.as_bytes()).into();
    let context = crate::context_policy::ContextVerificationPolicy {
        key: context_key,
        key_id: context_id,
    };

    for fault in [
        crate::compiled_policy::FaultVerificationPolicy {
            key: context_key,
            key_id: context_id,
        },
        crate::compiled_policy::FaultVerificationPolicy {
            key: fault_key,
            key_id: context_id,
        },
        crate::compiled_policy::FaultVerificationPolicy {
            key: context_key,
            key_id: fault_id,
        },
    ] {
        assert!(!crate::context_policy::authorities_are_distinct(
            &context, &fault
        ));
    }
    let distinct = crate::compiled_policy::FaultVerificationPolicy {
        key: fault_key,
        key_id: fault_id,
    };
    assert!(crate::context_policy::authorities_are_distinct(
        &context, &distinct
    ));
    let selected = crate::context_policy::select_distinct_policy(
        Some(crate::context_policy::ContextVerificationPolicy {
            key: context_key,
            key_id: context_id,
        }),
        Some(distinct),
    );
    assert!(selected.is_some(), "distinct valid authorities must load");
    assert!(
        crate::context_policy::select_distinct_policy(Some(context), None).is_none(),
        "missing or malformed fault policy must keep context authority unavailable"
    );
}

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::compiled_policy_match::matches;
use crate::compiled_policy::FaultVerificationPolicy;
use crate::context_policy::ContextVerificationPolicy;

fn check(pins: [[u8; 32]; 4], context: bool, fault: bool, shared: bool) -> bool {
    let context_key = SigningKey::from_bytes(&[1; 32]).verifying_key();
    let fault_key = SigningKey::from_bytes(&[if shared { 1 } else { 2 }; 32]).verifying_key();
    matches(
        context.then_some(ContextVerificationPolicy {
            key: context_key,
            key_id: Sha256::digest(context_key.as_bytes()).into(),
        }),
        fault.then_some(FaultVerificationPolicy {
            key: fault_key,
            key_id: Sha256::digest(fault_key.as_bytes()).into(),
        }),
        pins[0],
        pins[1],
        pins[2],
        pins[3],
    )
}

#[test]
fn requires_both_distinct_compiled_authorities_and_all_four_exact_pins() {
    let context = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let fault = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    let pins = [
        context,
        Sha256::digest(context).into(),
        fault,
        Sha256::digest(fault).into(),
    ];
    assert!(check(pins, true, true, false));
    for index in 0..4 {
        let mut wrong = pins;
        wrong[index][0] ^= 1;
        assert!(!check(wrong, true, true, false));
    }
    assert!(!check(pins, false, true, false));
    assert!(!check(pins, true, false, false));
    assert!(!check(pins, false, false, false));
    assert!(!check(
        [pins[0], pins[1], pins[0], pins[1]],
        true,
        true,
        true
    ));
}

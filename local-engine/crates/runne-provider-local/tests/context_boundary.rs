//! Context boundary (Plan Task 21 Step 1): limit−1 / limit /
//! limit+1 → pass / pass / reject, all BEFORE any host effect
//! (the admission is a pure function; there is no host to start).

use runne_local_model::tokenizer_quote::QuoteRevision;
use runne_provider_local::context_admission::{ContextAdmission, ContextAdmissionError};

const CONTEXT_LIMIT: u64 = 4096;
const RESERVED_OUTPUT: u64 = 512;
const OVERHEAD: u64 = 8;

fn admission() -> ContextAdmission {
    ContextAdmission {
        revision: QuoteRevision::IdentityBytesV1,
        context_limit: CONTEXT_LIMIT,
        reserved_output_tokens: RESERVED_OUTPUT,
        template_overhead_tokens: OVERHEAD,
    }
}

fn input_of_bytes(n: usize) -> Vec<u8> {
    vec![b'a'; n]
}

#[test]
fn limit_minus_one_and_limit_pass() {
    let allowed = CONTEXT_LIMIT - RESERVED_OUTPUT;
    // limit−1: quoted = allowed − 1 (overhead already inside the
    // quote), passes.
    let a = admission();
    let below = a
        .admit(&input_of_bytes((allowed - OVERHEAD - 1) as usize))
        .expect("limit-1 passes");
    assert_eq!(below.quoted_tokens, allowed - 1);
    // limit: exactly at the envelope passes.
    let at = admission()
        .admit(&input_of_bytes((allowed - OVERHEAD) as usize))
        .expect("limit passes");
    assert_eq!(at.quoted_tokens, allowed);
}

#[test]
fn limit_plus_one_rejects_before_host_effect() {
    let allowed = CONTEXT_LIMIT - RESERVED_OUTPUT;
    let err = admission()
        .admit(&input_of_bytes((allowed - OVERHEAD + 1) as usize))
        .expect_err("limit+1");
    assert_eq!(
        err,
        ContextAdmissionError::ContextExceeded {
            quoted_tokens: allowed + 1,
            context_limit: CONTEXT_LIMIT,
            reserved_output_tokens: RESERVED_OUTPUT,
        }
    );
    // Pure function: the same input yields the same reject; nothing
    // was started, nothing to roll back.
    let err2 = admission()
        .admit(&input_of_bytes((allowed - OVERHEAD + 1) as usize))
        .expect_err("again");
    assert_eq!(err, err2);
}

#[test]
fn display_is_sanitized_counts_only() {
    // Long enough to breach; contains content that must never leak.
    let mut long = b"sk-super-secret-prompt-material ".to_vec();
    while (long.len() as u64) <= CONTEXT_LIMIT - RESERVED_OUTPUT - OVERHEAD {
        long.extend_from_slice(b" more-secret-material");
    }
    let err = admission().admit(&long).expect_err("over the envelope");
    let text = err.to_string();
    assert!(!text.contains("secret"), "prompt content never leaks");
    assert!(text.contains("4096"), "limit present");
}

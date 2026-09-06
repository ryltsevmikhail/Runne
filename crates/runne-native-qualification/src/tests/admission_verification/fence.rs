use serde_json::json;

use super::{NOW, expected, signed_pair, verifier};

#[test]
fn fingerprint_binds_signed_context_identity_and_intervals() {
    let fingerprint = |admission| {
        verifier()
            .verify_exact_for_fence_borrowed(
                &admission,
                expected().candidate,
                expected().raw_tuple,
                NOW,
            )
            .unwrap()
            .fingerprint()
    };
    let baseline = fingerprint(signed_pair(|_| {}, |_| {}));
    assert_eq!(baseline, fingerprint(signed_pair(|_| {}, |_| {})));
    for (field, replacement) in [
        ("context_id", json!("55".repeat(32))),
        ("expires_at", json!(NOW + 299)),
        ("issued_at", json!(NOW - 1)),
    ] {
        assert_ne!(
            baseline,
            fingerprint(signed_pair(|context| context[field] = replacement, |_| {}))
        );
    }
}

#[test]
fn verification_mints_one_complete_combined_fact_set() {
    let admission = signed_pair(|_| {}, |_| {});
    let facts = verifier()
        .verify_exact_for_fence_borrowed(
            &admission,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        )
        .expect("valid pair mints fence facts");

    assert_eq!(facts.context_id(), [0x33; 32]);
    assert_eq!(facts.context_nonce(), [0x44; 32]);
    assert_eq!(facts.ticket_id(), [0x11; 32]);
    assert_eq!(facts.ticket_nonce(), [0x22; 32]);
    assert_eq!(
        facts.scenario(),
        crate::QualificationScenario::MacosXpcDpkV1
    );
    assert_eq!(
        facts.selector(),
        crate::QualificationFaultSelector::BeforeNativeEffect
    );
    assert_eq!(
        facts.process_role(),
        crate::QualificationProcessRole::Service
    );
    assert_eq!(facts.candidate_sha256(), [0xaa; 32]);
    assert_eq!(facts.raw_v3_tuple_sha256(), [0xbb; 32]);
    assert_eq!(facts.source_revision(), [0xcc; 20]);
    assert_eq!(facts.workflow_run_id(), "run-42");
    assert_eq!(facts.namespace_sha256(), [0xdd; 32]);
    assert_eq!(facts.context_issued_at(), NOW);
    assert_eq!(facts.context_expires_at(), NOW + 300);
    assert_eq!(facts.ticket_issued_at(), NOW);
    assert_eq!(facts.ticket_expires_at(), NOW + 600);
    assert_ne!(facts.ticket_sha256(), [0; 32]);
}

#[test]
fn facts_are_not_minted_for_any_combined_verification_failure() {
    let wrong_pair = signed_pair(|_| {}, |ticket| ticket["workflow_run_id"] = json!("run-43"));
    for (admission, candidate, raw_tuple, now) in [
        (wrong_pair, expected().candidate, expected().raw_tuple, NOW),
        (
            signed_pair(|_| {}, |_| {}),
            [0xab; 32],
            expected().raw_tuple,
            NOW,
        ),
        (
            signed_pair(|_| {}, |_| {}),
            expected().candidate,
            [0xbc; 32],
            NOW,
        ),
        (
            signed_pair(|_| {}, |_| {}),
            expected().candidate,
            expected().raw_tuple,
            NOW + 601,
        ),
    ] {
        assert!(
            verifier()
                .verify_exact_for_fence_borrowed(&admission, candidate, raw_tuple, now)
                .is_err()
        );
    }
}

#[test]
fn facts_reject_crossed_selector_and_role_bindings() {
    let ticket_crossed = signed_pair(
        |_| {},
        |ticket| {
            ticket["selector"] = json!("kill_after_native_effect");
        },
    );
    let context_crossed = signed_pair(
        |context| {
            context["selector"] = json!("kill_runtime_process");
            context["process_role"] = json!("runtime");
        },
        |_| {},
    );
    for admission in [ticket_crossed, context_crossed] {
        assert!(
            verifier()
                .verify_exact_for_fence_borrowed(
                    &admission,
                    expected().candidate,
                    expected().raw_tuple,
                    NOW,
                )
                .is_err()
        );
    }
}

#[test]
fn facts_are_minted_only_once_for_replayed_admission() {
    let admission = signed_pair(|_| {}, |_| {});
    let mut verifier = verifier();
    verifier
        .verify_exact_for_fence_borrowed(
            &admission,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        )
        .expect("first exact verification");
    assert!(
        verifier
            .verify_exact_for_fence_borrowed(
                &admission,
                expected().candidate,
                expected().raw_tuple,
                NOW,
            )
            .is_err()
    );
}

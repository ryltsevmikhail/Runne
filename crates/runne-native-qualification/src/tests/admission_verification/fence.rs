use serde_json::json;

use super::{NOW, expected, signed_pair, verifier};

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

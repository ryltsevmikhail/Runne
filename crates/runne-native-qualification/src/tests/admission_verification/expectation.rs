use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{
    NOW, admission_bundle, sign, sign_run_context, signed_pair, unsigned_run_context,
    unsigned_ticket, verifier,
};
use crate::{
    PendingQualificationAdmission, QualificationAdmissionVerifier,
    QualificationRunContextExpectation,
};

fn expected_for_ticket(
    ticket_change: impl FnOnce(&mut Value),
) -> QualificationRunContextExpectation {
    let mut ticket = unsigned_ticket();
    ticket_change(&mut ticket);
    let ticket = sign(&ticket, &SigningKey::from_bytes(&[7; 32]));
    super::super::run_context_expectation(Sha256::digest(ticket).into())
}

fn zero_expected(ticket_sha256: [u8; 32]) -> QualificationRunContextExpectation {
    QualificationRunContextExpectation::new(
        crate::QualificationScenario::MacosXpcDpkV1,
        crate::QualificationFaultSelector::BeforeNativeEffect,
        crate::QualificationProcessRole::Service,
        [0; 32],
        [0; 32],
        [0xcc; 20],
        "run-42",
        [0xdd; 32],
        ticket_sha256,
    )
    .expect("canonical zero expectation")
}

fn verify(
    verifier: &mut QualificationAdmissionVerifier,
    admission: &crate::PendingQualificationAdmission,
    expected: &QualificationRunContextExpectation,
) -> bool {
    verifier
        .verify_and_consume(admission, expected, NOW)
        .is_ok()
}

#[test]
fn complete_expectation_mints_exact_fence_facts_once() {
    let admission = signed_pair(|_| {}, |_| {});
    let expected = expected_for_ticket(|_| {});
    let facts = verifier()
        .verify_and_consume(&admission, &expected, NOW)
        .expect("exact context and ticket must mint fence facts");

    assert_eq!(facts.context_id(), [0x33; 32]);
    assert_eq!(facts.ticket_id(), [0x11; 32]);
    assert_eq!(facts.source_revision(), [0xcc; 20]);
    assert_eq!(facts.workflow_run_id(), "run-42");
    assert_eq!(facts.namespace_sha256(), [0xdd; 32]);
}

#[test]
fn complete_expectation_rejects_every_independent_context_binding() {
    let expected = expected_for_ticket(|_| {});
    let cases: [(&str, fn(&mut Value)); 5] = [
        ("source", |context| {
            context["source_revision"] = json!("ee".repeat(20))
        }),
        ("workflow", |context| {
            context["workflow_run_id"] = json!("run-43")
        }),
        ("namespace", |context| {
            context["namespace_sha256"] = json!("ee".repeat(32))
        }),
        ("candidate", |context| {
            context["candidate_sha256"] = json!("ee".repeat(32))
        }),
        ("raw tuple", |context| {
            context["release_tuple_v3_sha256"] = json!("ee".repeat(32))
        }),
    ];
    for (name, change) in cases {
        assert!(
            !verify(&mut verifier(), &signed_pair(change, |_| {}), &expected),
            "{name} mismatch must reject before a fence is minted"
        );
    }

    let ticket = sign(&unsigned_ticket(), &SigningKey::from_bytes(&[7; 32]));
    let mut invalid_scenario = unsigned_run_context(Sha256::digest(&ticket).into());
    invalid_scenario["scenario_id"] = json!("other");
    let invalid_scenario = sign_run_context(&invalid_scenario, &SigningKey::from_bytes(&[9; 32]));
    assert!(
        PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &invalid_scenario,
            &ticket,
        ))
        .is_err(),
        "an unknown signed scenario must fail before verification"
    );

    let role = signed_pair(
        |context| {
            context["selector"] = json!("kill_runtime_process");
            context["process_role"] = json!("runtime");
        },
        |_| {},
    );
    assert!(!verify(&mut verifier(), &role, &expected));

    let selector = signed_pair(
        |context| context["selector"] = json!("kill_after_native_effect"),
        |_| {},
    );
    assert!(!verify(&mut verifier(), &selector, &expected));
}

#[test]
fn complete_expectation_binds_ticket_and_consumes_context_before_fault_rejection() {
    let ticket_change = |ticket: &mut Value| ticket["source_revision"] = json!("ee".repeat(20));
    let admission = signed_pair(|_| {}, ticket_change);
    let expected = expected_for_ticket(ticket_change);
    let mut authority = verifier();

    assert!(
        !verify(&mut authority, &admission, &expected),
        "fault assertions must be verified after the complete context"
    );

    let corrected = signed_pair(|_| {}, |_| {});
    let corrected_expected = expected_for_ticket(|_| {});
    assert!(
        !verify(&mut authority, &corrected, &corrected_expected),
        "the accepted context id and nonce must be consumed before fault rejection"
    );
    assert!(
        verify(&mut verifier(), &corrected, &corrected_expected),
        "the corrected ticket is otherwise valid under a fresh verifier"
    );
}

#[test]
fn context_failure_does_not_consume_the_corresponding_fault_ticket() {
    let expected = expected_for_ticket(|_| {});
    let invalid_context = signed_pair(
        |context| context["namespace_sha256"] = json!("ee".repeat(32)),
        |_| {},
    );
    let valid_context = signed_pair(|_| {}, |_| {});
    let mut authority = verifier();

    assert!(!verify(&mut authority, &invalid_context, &expected));
    assert!(
        verify(&mut authority, &valid_context, &expected),
        "fault ticket must remain available when context verification fails"
    );
}

#[test]
fn complete_expectation_rejects_zero_candidate_or_raw_before_consumption() {
    let zero_pair = signed_pair(
        |context| {
            context["candidate_sha256"] = json!("00".repeat(32));
            context["release_tuple_v3_sha256"] = json!("00".repeat(32));
        },
        |ticket| {
            ticket["candidate_sha256"] = json!("00".repeat(32));
            ticket["release_tuple_v3_sha256"] = json!("00".repeat(32));
        },
    );
    let zero_ticket = sign(
        &{
            let mut ticket = unsigned_ticket();
            ticket["candidate_sha256"] = json!("00".repeat(32));
            ticket["release_tuple_v3_sha256"] = json!("00".repeat(32));
            ticket
        },
        &SigningKey::from_bytes(&[7; 32]),
    );
    let zero_expected = zero_expected(Sha256::digest(zero_ticket).into());
    let normal_pair = signed_pair(|_| {}, |_| {});
    let normal_expected = expected_for_ticket(|_| {});
    let mut authority = verifier();

    assert!(!verify(&mut authority, &zero_pair, &zero_expected));
    assert!(
        verify(&mut authority, &normal_pair, &normal_expected),
        "zero installed facts must fail before consuming replay state"
    );
}

#[test]
fn complete_expectation_rejects_replayed_admission() {
    let admission = signed_pair(|_| {}, |_| {});
    let expected = expected_for_ticket(|_| {});
    let mut authority = verifier();

    assert!(verify(&mut authority, &admission, &expected));
    assert!(!verify(&mut authority, &admission, &expected));
}

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::super::{
    NOW, admission_bundle, expected, sign, sign_run_context, signed_pair, unsigned_run_context,
    unsigned_ticket, verifier,
};
use super::{service, service_pair, verify_service};
use crate::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, QualificationFaultSelector,
};

#[test]
fn service_combined_verification_rejects_foreign_and_crossed_roles() {
    let foreign_pairs = [
        signed_pair(
            |context| {
                context["selector"] = json!("kill_writer_process");
                context["process_role"] = json!("writer");
            },
            |ticket| {
                ticket["selector"] = json!("kill_writer_process");
                ticket["process_role"] = json!("writer");
            },
        ),
        signed_pair(
            |context| {
                context["selector"] = json!("kill_desktop_process");
                context["process_role"] = json!("desktop");
            },
            |ticket| {
                ticket["selector"] = json!("kill_desktop_process");
                ticket["process_role"] = json!("desktop");
            },
        ),
        signed_pair(
            |context| {
                context["selector"] = json!("kill_runtime_process");
                context["process_role"] = json!("runtime");
            },
            |ticket| {
                ticket["selector"] = json!("kill_runtime_process");
                ticket["process_role"] = json!("runtime");
            },
        ),
        signed_pair(
            |context| service(QualificationFaultSelector::BeforeReply, context),
            |ticket| service(QualificationFaultSelector::AfterReply, ticket),
        ),
    ];
    for admission in foreign_pairs {
        assert!(!verify_service(
            &mut verifier(),
            &admission,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        ));
    }
}

#[test]
fn service_combined_verification_rejects_cross_member_bindings_and_installed_tuple_mismatches() {
    for admission in [
        signed_pair(
            |context| service(QualificationFaultSelector::BeforeNativeEffect, context),
            |ticket| {
                service(QualificationFaultSelector::BeforeNativeEffect, ticket);
                ticket["source_revision"] = json!("ce".repeat(20));
            },
        ),
        signed_pair(
            |context| service(QualificationFaultSelector::BeforeNativeEffect, context),
            |ticket| {
                service(QualificationFaultSelector::BeforeNativeEffect, ticket);
                ticket["workflow_run_id"] = json!("run-43");
            },
        ),
        signed_pair(
            |context| service(QualificationFaultSelector::BeforeNativeEffect, context),
            |ticket| {
                service(QualificationFaultSelector::BeforeNativeEffect, ticket);
                ticket["namespace_sha256"] = json!("de".repeat(32));
            },
        ),
    ] {
        assert!(!verify_service(
            &mut verifier(),
            &admission,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        ));
    }
    for (candidate, raw_tuple) in [
        ([0; 32], expected().raw_tuple),
        (expected().candidate, [0; 32]),
        ([0xab; 32], expected().raw_tuple),
        (expected().candidate, [0xbc; 32]),
    ] {
        assert!(!verify_service(
            &mut verifier(),
            &service_pair(QualificationFaultSelector::BeforeNativeEffect),
            candidate,
            raw_tuple,
            NOW,
        ));
    }
}

#[test]
fn service_combined_verification_rejects_authority_and_freshness_failures() {
    let unavailable = QualificationAdmissionVerifier::from_compiled_policy();
    assert!(!verify_service(
        &mut { unavailable },
        &service_pair(QualificationFaultSelector::BeforeNativeEffect),
        expected().candidate,
        expected().raw_tuple,
        NOW,
    ));

    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let ticket = sign(&unsigned_ticket(), &fault_key);
    let foreign_context = sign_run_context(
        &unsigned_run_context(Sha256::digest(&ticket).into()),
        &SigningKey::from_bytes(&[10; 32]),
    );
    let foreign_context = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
        &foreign_context,
        &ticket,
    ))
    .unwrap();
    assert!(!verify_service(
        &mut verifier(),
        &foreign_context,
        expected().candidate,
        expected().raw_tuple,
        NOW,
    ));

    let foreign_ticket = sign(&unsigned_ticket(), &SigningKey::from_bytes(&[8; 32]));
    let context = sign_run_context(
        &unsigned_run_context(Sha256::digest(&foreign_ticket).into()),
        &context_key,
    );
    let foreign_ticket = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
        &context,
        &foreign_ticket,
    ))
    .unwrap();
    assert!(!verify_service(
        &mut verifier(),
        &foreign_ticket,
        expected().candidate,
        expected().raw_tuple,
        NOW,
    ));

    for admission in [
        signed_pair(
            |context| {
                service(QualificationFaultSelector::BeforeNativeEffect, context);
                context["issued_at"] = json!(NOW + 1);
            },
            |ticket| service(QualificationFaultSelector::BeforeNativeEffect, ticket),
        ),
        signed_pair(
            |context| service(QualificationFaultSelector::BeforeNativeEffect, context),
            |ticket| {
                service(QualificationFaultSelector::BeforeNativeEffect, ticket);
                ticket["issued_at"] = json!(NOW + 1);
            },
        ),
        signed_pair(
            |context| {
                service(QualificationFaultSelector::BeforeNativeEffect, context);
                context["issued_at"] = json!(NOW - 601);
                context["expires_at"] = json!(NOW);
            },
            |ticket| service(QualificationFaultSelector::BeforeNativeEffect, ticket),
        ),
    ] {
        assert!(!verify_service(
            &mut verifier(),
            &admission,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        ));
    }
}

#[test]
fn service_combined_verification_consumes_pair_and_ticket_replays() {
    let admission = service_pair(QualificationFaultSelector::BeforeNativeEffect);
    let mut replay_verifier = verifier();
    assert!(verify_service(
        &mut replay_verifier,
        &admission,
        expected().candidate,
        expected().raw_tuple,
        NOW,
    ));
    assert!(!verify_service(
        &mut replay_verifier,
        &admission,
        expected().candidate,
        expected().raw_tuple,
        NOW,
    ));

    let fault_key = SigningKey::from_bytes(&[7; 32]);
    let context_key = SigningKey::from_bytes(&[9; 32]);
    let mut ticket_value = unsigned_ticket();
    service(
        QualificationFaultSelector::BeforeNativeEffect,
        &mut ticket_value,
    );
    let ticket = sign(&ticket_value, &fault_key);
    let digest = Sha256::digest(&ticket).into();
    let first = sign_run_context(&unsigned_run_context(digest), &context_key);
    let mut second = unsigned_run_context(digest);
    service(QualificationFaultSelector::BeforeNativeEffect, &mut second);
    second["context_id"] = json!("55".repeat(32));
    second["nonce"] = json!(URL_SAFE_NO_PAD.encode([0x66; 32]));
    let second = sign_run_context(&second, &context_key);
    let mut ticket_replay_verifier = verifier();
    for (index, context) in [first, second].into_iter().enumerate() {
        let admission = PendingQualificationAdmission::from_admitted_bundle(admission_bundle(
            &context, &ticket,
        ))
        .unwrap();
        assert_eq!(
            verify_service(
                &mut ticket_replay_verifier,
                &admission,
                expected().candidate,
                expected().raw_tuple,
                NOW,
            ),
            index == 0,
        );
    }
}

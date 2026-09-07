use serde_json::{Value, json};

use super::{NOW, expected, signed_pair, verifier};
use crate::{
    PendingQualificationAdmission, QualificationAdmissionVerifier, QualificationFaultSelector,
    QualificationProcessRole,
};

const SERVICE_SELECTORS: [QualificationFaultSelector; 10] = [
    QualificationFaultSelector::BeforeServiceConsume,
    QualificationFaultSelector::AfterServiceConsume,
    QualificationFaultSelector::BeforeNativeEffect,
    QualificationFaultSelector::AfterNativeEffect,
    QualificationFaultSelector::BeforeReadback,
    QualificationFaultSelector::AfterReadback,
    QualificationFaultSelector::BeforeReply,
    QualificationFaultSelector::AfterReply,
    QualificationFaultSelector::ServiceLaunchdRestart,
    QualificationFaultSelector::RegistrationAckLoss,
];

fn service(selector: QualificationFaultSelector, value: &mut Value) {
    value["selector"] = json!(selector.as_str());
    value["process_role"] = json!("service");
}

fn service_pair(selector: QualificationFaultSelector) -> PendingQualificationAdmission {
    signed_pair(
        |context| service(selector, context),
        |ticket| service(selector, ticket),
    )
}

fn verify_service(
    verifier: &mut QualificationAdmissionVerifier,
    admission: &PendingQualificationAdmission,
    candidate: [u8; 32],
    raw_tuple: [u8; 32],
    now: u64,
) -> bool {
    verifier
        .verify_exact_service_fault_borrowed(admission, candidate, raw_tuple, now)
        .is_ok()
}

#[test]
fn service_combined_verification_accepts_every_canonical_service_selector() {
    for selector in SERVICE_SELECTORS {
        let fault = verifier()
            .verify_exact_service_fault_borrowed(
                &service_pair(selector),
                expected().candidate,
                expected().raw_tuple,
                NOW,
            )
            .expect("independently signed Service pair");
        assert_eq!(fault.selector(), selector);
        assert_eq!(fault.process_role(), QualificationProcessRole::Service);
        assert_eq!(selector.process_role(), QualificationProcessRole::Service);
    }
}

mod rejection;

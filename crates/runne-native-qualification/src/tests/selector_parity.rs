use ed25519_dalek::SigningKey;
use serde_json::json;

use super::{NOW, context, sign, unsigned_ticket};
use crate::{
    QualificationFaultError, QualificationFaultSelector, QualificationFaultVerifier,
    QualificationProcessRole,
};

const SELECTOR_ROLES: &[(
    QualificationFaultSelector,
    &str,
    QualificationProcessRole,
    &str,
)] = &[
    (
        QualificationFaultSelector::BeforeServiceConsume,
        "kill_before_service_consume",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::AfterServiceConsume,
        "kill_after_service_consume",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::BeforeNativeEffect,
        "kill_before_native_effect",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::AfterNativeEffect,
        "kill_after_native_effect",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::BeforeReadback,
        "kill_before_readback",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::AfterReadback,
        "kill_after_readback",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::BeforeReply,
        "kill_before_reply",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::AfterReply,
        "kill_after_reply",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::BeforeLifecycleCas,
        "kill_before_lifecycle_cas",
        QualificationProcessRole::Runtime,
        "runtime",
    ),
    (
        QualificationFaultSelector::AfterLifecycleCas,
        "kill_after_lifecycle_cas",
        QualificationProcessRole::Runtime,
        "runtime",
    ),
    (
        QualificationFaultSelector::DesktopProcess,
        "kill_desktop_process",
        QualificationProcessRole::Desktop,
        "desktop",
    ),
    (
        QualificationFaultSelector::WriterProcess,
        "kill_writer_process",
        QualificationProcessRole::Writer,
        "writer",
    ),
    (
        QualificationFaultSelector::RuntimeProcess,
        "kill_runtime_process",
        QualificationProcessRole::Runtime,
        "runtime",
    ),
    (
        QualificationFaultSelector::ServiceLaunchdRestart,
        "kill_service_launchd_restart",
        QualificationProcessRole::Service,
        "service",
    ),
    (
        QualificationFaultSelector::RegistrationAckLoss,
        "kill_registration_ack_loss",
        QualificationProcessRole::Service,
        "service",
    ),
];

const ROLES: &[(QualificationProcessRole, &str)] = &[
    (QualificationProcessRole::Desktop, "desktop"),
    (QualificationProcessRole::Writer, "writer"),
    (QualificationProcessRole::Runtime, "runtime"),
    (QualificationProcessRole::Service, "service"),
];

#[test]
fn every_selector_parser_and_verifier_share_the_closed_role_mapping() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for (selector, wire_selector, role, wire_role) in SELECTOR_ROLES {
        let mut value = unsigned_ticket();
        value["selector"] = json!(wire_selector);
        value["process_role"] = json!(wire_role);
        let fault = QualificationFaultVerifier::for_test(key.verifying_key())
            .verify_and_consume(&sign(&value, &key), &context(*selector, *role), NOW)
            .expect("valid selector/role pair");
        assert_eq!(fault.selector(), *selector);
        assert_eq!(fault.process_role(), *role);

        for (wrong_role, wrong_wire_role) in ROLES {
            if wrong_role == role {
                continue;
            }
            let mut invalid = value.clone();
            invalid["process_role"] = json!(wrong_wire_role);
            assert_eq!(
                QualificationFaultVerifier::for_test(key.verifying_key())
                    .verify_and_consume(
                        &sign(&invalid, &key),
                        &context(*selector, *wrong_role),
                        NOW,
                    )
                    .expect_err("wrong role must fail"),
                QualificationFaultError::InvalidTicket,
                "{wire_selector}/{wrong_wire_role}"
            );
        }
    }
}

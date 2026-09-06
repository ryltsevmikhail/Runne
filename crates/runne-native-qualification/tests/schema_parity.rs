use jsonschema::{Draft, JSONSchema};
use runne_native_qualification::{QualificationFaultSelector, QualificationProcessRole};
use serde_json::{Value, json};

fn schema_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/schemas/macos-xpc-dpk-fault-ticket-v1.schema.json"
    ))
    .expect("schema JSON")
}

fn schema() -> JSONSchema {
    let value = schema_value();
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("valid schema")
}

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

fn ticket() -> Value {
    json!({
        "schema_version": "runne/macos-xpc-dpk-fault-ticket/v1",
        "ticket_id": "11".repeat(32),
        "selector": "kill_before_native_effect",
        "process_role": "service",
        "candidate_sha256": "aa".repeat(32),
        "release_tuple_v3_sha256": "bb".repeat(32),
        "source_revision": "cc".repeat(20),
        "workflow_run_id": "run-42",
        "namespace_sha256": "dd".repeat(32),
        "issued_at": 1_800_000_000_u64,
        "expires_at": 1_800_000_600_u64,
        "nonce": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "ee".repeat(32),
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }
    })
}

#[test]
fn schema_accepts_only_the_closed_canonical_shape() {
    let schema = schema();
    assert!(schema.is_valid(&ticket()));
    for mutation in [
        ("extra", json!(true)),
        ("selector", json!("kill_arbitrary_process")),
        ("nonce", json!("AAAA=")),
    ] {
        let mut value = ticket();
        value[mutation.0] = mutation.1;
        assert!(!schema.is_valid(&value), "{}", mutation.0);
    }
    let mut wrong_role = ticket();
    wrong_role["process_role"] = json!("runtime");
    assert!(!schema.is_valid(&wrong_role));
    let mut signature_field = ticket();
    signature_field["signature"]["extra"] = json!(true);
    assert!(!schema.is_valid(&signature_field));
}

#[test]
fn all_rust_selector_role_pairs_match_the_schema_and_reject_other_roles() {
    let value = schema_value();
    let schema = schema();
    let schema_selectors = value["properties"]["selector"]["enum"]
        .as_array()
        .expect("selector enum");
    assert_eq!(schema_selectors.len(), SELECTOR_ROLES.len());
    for (selector, wire_selector, role, wire_role) in SELECTOR_ROLES {
        assert_eq!(selector.as_str(), *wire_selector);
        assert_eq!(selector.process_role(), *role);
        assert!(schema_selectors.iter().any(|value| value == wire_selector));
        let mut valid = ticket();
        valid["selector"] = json!(wire_selector);
        valid["process_role"] = json!(wire_role);
        assert!(schema.is_valid(&valid), "{wire_selector}/{wire_role}");
        for wrong_role in ["desktop", "writer", "runtime", "service"] {
            if wrong_role == *wire_role {
                continue;
            }
            let mut invalid = valid.clone();
            invalid["process_role"] = json!(wrong_role);
            assert!(!schema.is_valid(&invalid), "{wire_selector}/{wrong_role}");
        }
    }
}

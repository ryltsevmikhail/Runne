use jsonschema::{Draft, JSONSchema};
use serde_json::{Value, json};

fn schema_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/schemas/macos-xpc-dpk-run-context-v1.schema.json"
    ))
    .expect("runner-context schema JSON")
}

fn schema() -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_value())
        .expect("valid runner-context schema")
}

fn context() -> Value {
    json!({
        "schema_version": "runne/macos-xpc-dpk-run-context/v1",
        "context_id": "33".repeat(32),
        "scenario_id": "macos-xpc-dpk-v1",
        "selector": "kill_before_native_effect",
        "process_role": "service",
        "candidate_sha256": "aa".repeat(32),
        "release_tuple_v3_sha256": "bb".repeat(32),
        "source_revision": "cc".repeat(20),
        "workflow_run_id": "run-42",
        "namespace_sha256": "dd".repeat(32),
        "ticket_sha256": "55".repeat(32),
        "issued_at": 1_800_000_000_u64,
        "expires_at": 1_800_000_300_u64,
        "nonce": "REREREREREREREREREREREREREREREREREREREREREQ",
        "signature": {
            "algorithm": "ed25519",
            "key_id": "ee".repeat(32),
            "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }
    })
}

#[test]
fn runner_context_schema_accepts_only_closed_role_bound_shape() {
    let schema = schema();
    assert!(schema.is_valid(&context()));
    for (field, replacement) in [
        ("extra", json!(true)),
        ("scenario_id", json!("other")),
        ("selector", json!("kill_arbitrary_process")),
        ("nonce", json!("AAAA=")),
    ] {
        let mut value = context();
        value[field] = replacement;
        assert!(!schema.is_valid(&value), "{field}");
    }
    let mut wrong_role = context();
    wrong_role["process_role"] = json!("runtime");
    assert!(!schema.is_valid(&wrong_role));
    let mut signature_field = context();
    signature_field["signature"]["extra"] = json!(true);
    assert!(!schema.is_valid(&signature_field));
}

#[test]
fn runner_context_schema_and_rust_selectors_are_exactly_equal() {
    let value = schema_value();
    let schema = schema();
    let selectors = value["properties"]["selector"]["enum"]
        .as_array()
        .expect("selector enum");
    assert_eq!(selectors.len(), 15);
    for selector in [
        runne_native_qualification::QualificationFaultSelector::BeforeServiceConsume,
        runne_native_qualification::QualificationFaultSelector::AfterServiceConsume,
        runne_native_qualification::QualificationFaultSelector::BeforeNativeEffect,
        runne_native_qualification::QualificationFaultSelector::AfterNativeEffect,
        runne_native_qualification::QualificationFaultSelector::BeforeReadback,
        runne_native_qualification::QualificationFaultSelector::AfterReadback,
        runne_native_qualification::QualificationFaultSelector::BeforeReply,
        runne_native_qualification::QualificationFaultSelector::AfterReply,
        runne_native_qualification::QualificationFaultSelector::BeforeLifecycleCas,
        runne_native_qualification::QualificationFaultSelector::AfterLifecycleCas,
        runne_native_qualification::QualificationFaultSelector::DesktopProcess,
        runne_native_qualification::QualificationFaultSelector::WriterProcess,
        runne_native_qualification::QualificationFaultSelector::RuntimeProcess,
        runne_native_qualification::QualificationFaultSelector::ServiceLaunchdRestart,
        runne_native_qualification::QualificationFaultSelector::RegistrationAckLoss,
    ] {
        let wire = selector.as_str();
        assert!(selectors.iter().any(|value| value == wire), "{wire}");
        let mut candidate = context();
        candidate["selector"] = json!(wire);
        candidate["process_role"] = json!(match selector.process_role() {
            runne_native_qualification::QualificationProcessRole::Desktop => "desktop",
            runne_native_qualification::QualificationProcessRole::Writer => "writer",
            runne_native_qualification::QualificationProcessRole::Runtime => "runtime",
            runne_native_qualification::QualificationProcessRole::Service => "service",
        });
        assert!(schema.is_valid(&candidate), "{wire}");
    }
}

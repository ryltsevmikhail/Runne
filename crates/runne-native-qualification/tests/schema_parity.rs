use jsonschema::{Draft, JSONSchema};
use serde_json::{Value, json};

fn schema() -> JSONSchema {
    let value: Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/macos-xpc-dpk-fault-ticket-v1.schema.json"
    ))
    .expect("schema JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("valid schema")
}

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

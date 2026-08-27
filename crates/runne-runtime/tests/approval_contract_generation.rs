use std::fs;

use runne_runtime::contract_generation::generate_ui_contract;

#[test]
fn generated_contract_publishes_the_closed_approval_query_and_decision_paths() {
    let output = tempfile::tempdir().expect("output");
    generate_ui_contract(output.path()).expect("generate");
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).expect("OpenAPI"))
            .expect("valid OpenAPI");
    let paths = document["paths"].as_object().expect("paths");

    for (path, method) in [
        ("/v1/approvals", "get"),
        ("/v1/approvals/{approvalId}", "get"),
        ("/v1/approvals/{approvalId}/decision", "post"),
    ] {
        assert!(
            paths.get(path).and_then(|item| item.get(method)).is_some(),
            "{method} {path}"
        );
    }
    assert!(
        output
            .path()
            .join("schemas/approval-v1.schema.json")
            .is_file()
    );
}

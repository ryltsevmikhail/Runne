#[test]
fn process_issuance_is_not_part_of_public_source_contract() {
    let issuance = include_str!("../../../src/discovery/issuance.rs");
    let publication = include_str!("../../../src/fixture/publication.rs");
    let crate_root = include_str!("../../../src/lib.rs");
    let (_, fixture_exports) = crate_root
        .split_once("pub use fixture::{")
        .expect("lib root must export fixture symbols");
    let (fixture_exports, _) = fixture_exports
        .split_once("};")
        .expect("fixture export block must close");
    let process = include_str!("../../../src/fixture/process.rs");
    let runtime = include_str!("../../../src/fixture/runtime.rs");
    let process_activation = include_str!("../../../src/fixture/runtime/process_activation.rs");
    let composition_tests = include_str!("../../../src/fixture/runtime_composition_tests.rs");
    let process_contract = include_str!("../../../../runne-tools/src/process_contract.rs");

    assert!(issuance.contains("#[cfg(test)]\n    pub(crate) fn issue_process_dispatch"));
    assert!(issuance.contains("pub(crate) fn issue_process_dispatch"));
    assert!(!issuance.contains("pub fn issue_process_dispatch"));
    assert!(!issuance.contains("#[allow(dead_code)]"));
    assert!(!runtime.contains("#[allow(dead_code)]"));
    assert!(!publication.contains("pub fn issue_process_dispatch"));
    assert!(!publication.contains("pub fn derive_process_identity_binding"));
    assert!(!fixture_exports.contains("derive_process_identity_binding"));
    assert!(process.contains("pub(in crate::fixture) fn derive_process_identity_binding"));
    assert!(runtime.contains("pub(super) fn compose_gateway"));
    assert!(process_activation.contains("let ledger = Arc::new(self.process_ledger_port());"));
    assert!(process_activation.contains("Arc::new(McpGenerationAuthority::new(binding)),"));
    assert!(process_activation.contains("ledger,"));
    assert!(composition_tests.contains("ProcessContractHostV1::new"));
    assert!(composition_tests.contains("ProcessClaimJournalMemoryV1::new"));
    assert!(process_contract.contains("#![cfg_attr(not(test), allow(dead_code, unused_imports))]"));
    assert!(process_contract.contains("mod host;") && process_contract.contains("mod journal_memory;"));
    assert!(process_contract.contains("pub use host::{ProcessContractHostSnapshotV1, ProcessContractHostV1"));
    assert!(process_contract.contains("pub use journal_memory::{ProcessClaimJournalMemorySnapshotV1, ProcessClaimJournalMemoryV1}"));
}

#[test]
fn issuance_rejects_normalized_secret_keys_and_values_before_capability_creation() {
    let published = published();
    let binding = binding(1, *published.discovery_digest());
    let tool_ref = published.snapshot().tool_refs()[0].clone();

    for (index, token) in [
        "api_key",
        "access_token",
        "refresh_token",
        "private_key",
        "session_secret",
    ]
    .iter()
    .enumerate()
    {
        for (case, input) in [
            ("key", json!({ (*token): "untrusted" })),
            (
                "embedded-key",
                json!({ (format!("embedded-{token}-material")): "untrusted" }),
            ),
            ("value", json!(*token)),
            ("embedded-value", json!(format!("embedded-{token}-material"))),
        ] {
            let error = match published.issue_dispatch(
                &binding,
                &tool_ref,
                McpInvocationId::new(format!("forbidden-{case}-{index}")).unwrap(),
                input,
            ) {
                Err(error) => error,
                Ok(_) => panic!("secret material unexpectedly issued a capability"),
            };
            assert!(matches!(error, McpDispatchCapabilityError::InvalidInput(_)));
            assert!(!format!("{error:?}").contains(*token));
            assert!(!format!("{error:?}").contains("untrusted"));
        }
    }
}

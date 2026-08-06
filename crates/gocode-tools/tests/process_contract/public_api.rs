#[test]
fn public_api_hides_dispatch_composition_authority() {
    let facade = include_str!("../../src/lib.rs");
    let contract = include_str!("../../src/process_contract.rs");
    for hidden in [
        "ProcessOrchestratorV1",
        "ProcessCancellationTokenV1",
        "ProcessMonotonicClockV1",
        "ProcessControlPortV1",
        "ProcessClaimJournalPort",
        "ProcessClaimKeyV1",
        "ProcessClaimRecordV1",
        "ProcessDispatchOutcomeV1",
    ] {
        assert!(!facade.contains(hidden), "root export: {hidden}");
    }
    for authority_module in ["claim", "control", "orchestrator"] {
        assert!(
            !contract.contains(&format!("pub use {authority_module}")),
            "facade authority export: {authority_module}"
        );
    }
    assert!(!contract.contains("pub fn dispatch"), "public dispatch");
}

#[test]
fn public_api_hides_executable_raw_output_route() {
    let facade = include_str!("../../src/lib.rs");
    let contract = include_str!("../../src/process_contract.rs");
    let output = include_str!("../../src/process_contract/output.rs");
    let collector = include_str!("../../src/process_contract/output/output_collector.rs");
    let payload = include_str!("../../src/process_contract/output/output_payload.rs");
    let settlement = include_str!("../../src/process_contract/settlement.rs");

    for hidden in [
        "ProcessOutputCollectorV1",
        "ProcessOutputCallerIdV1",
        "ProcessCapturedOutputV1",
        "TransientProcessOutputChannelV1",
        "ProcessTransientOutputPayloadV1",
        "ProcessOutputReadBudgetV1",
        "ProcessOutputSourceEventV1",
        "ProcessOutputSourcePortV1",
        "ProcessOutputStopReasonV1",
        "ProcessOutputStreamV1",
    ] {
        assert!(!facade.contains(hidden), "root output export: {hidden}");
        assert!(
            !contract.contains(&format!("pub use output::{hidden}")),
            "contract output export: {hidden}"
        );
        assert!(
            !output.contains(&format!("pub use {hidden}")),
            "output facade export: {hidden}"
        );
    }

    for (source, method) in [
        (collector, "pub fn collect"),
        (payload, "pub fn new"),
        (payload, "pub fn copy_for"),
        (payload, "pub fn stdout"),
        (payload, "pub fn stderr"),
        (payload, "pub const fn transient"),
        (settlement, "pub const fn transient"),
    ] {
        assert!(!source.contains(method), "public raw output method: {method}");
    }
}

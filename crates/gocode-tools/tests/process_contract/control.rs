#[test]
fn control_contract_exists_without_pid_only_entry_points() {
    let source = include_str!("../../src/process_contract/control.rs");
    assert!(source.contains("ProcessControlPortV1"));
    assert!(source.contains("pub(crate) trait ProcessControlPortV1"));
    assert!(!source.contains("pid"));
}

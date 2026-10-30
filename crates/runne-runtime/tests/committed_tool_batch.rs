use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind as K,
    ProviderTerminalDisposition, ProviderUsage,
};
use runne_runtime::provider_tool::CommittedToolProposalCollector;
fn events() -> Vec<ProviderStreamEvent> {
    vec![
        K::Started,
        K::ToolCallRequested {
            call_id: "one".into(),
            tool_name: "workspace.file.read".into(),
            arguments_json: "{}".into(),
        },
        K::ToolCallRequested {
            call_id: "two".into(),
            tool_name: "workspace.file.read".into(),
            arguments_json: "{}".into(),
        },
        K::Usage {
            usage: ProviderUsage::new(1, 2, 0, 0).unwrap(),
        },
        K::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::ToolCalls,
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(i, k)| ProviderStreamEvent::new(i as u64, k).unwrap())
    .collect()
}
#[test]
fn batch_is_opt_in_and_visible_only_after_authenticated_terminal() {
    let mut legacy =
        CommittedToolProposalCollector::new(0, String::new(), None, false, 8192).unwrap();
    for event in &events()[..2] {
        legacy.accept_committed(event, true).unwrap();
    }
    assert!(legacy.accept_committed(&events()[2], true).is_err());
    let mut batch = CommittedToolProposalCollector::new(0, String::new(), None, false, 8192)
        .unwrap()
        .with_max_calls(16)
        .unwrap();
    for event in &events()[..4] {
        batch.accept_committed(event, true).unwrap();
        assert!(batch.committed_calls().is_empty());
    }
    assert!(
        batch
            .accept_committed(&events()[4], true)
            .unwrap()
            .is_some()
    );
    assert_eq!(batch.committed_calls().len(), 2);
    assert_eq!(batch.committed_calls()[1].call_id, "two");
}

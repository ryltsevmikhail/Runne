use runne_local_store::{BoundedCanonicalId, NormalizedMutationCommand};

#[test]
fn task_run_submit_codec_keeps_legacy_promptless_tag_12_separate_from_prompted_tag_13() {
    let conversation = BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000901").unwrap();
    let workspace = BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000902").unwrap();
    let mut legacy_bytes = vec![1, 12];
    for id in [conversation.as_bytes(), workspace.as_bytes()] {
        legacy_bytes.extend(u16::try_from(id.len()).unwrap().to_be_bytes());
        legacy_bytes.extend(id);
    }
    let legacy = NormalizedMutationCommand::decode(&legacy_bytes).unwrap();
    assert_eq!(
        legacy,
        NormalizedMutationCommand::LegacySubmitTaskRun {
            conversation_id: conversation.clone(),
            workspace_id: workspace.clone(),
        }
    );
    assert_eq!(
        NormalizedMutationCommand::decode(&legacy.encode().unwrap()).unwrap(),
        legacy
    );

    let prompted = NormalizedMutationCommand::SubmitTaskRun {
        conversation_id: conversation,
        workspace_id: workspace,
        prompt: "Inspect recent changes".to_owned(),
    };
    assert_eq!(prompted.encode().unwrap()[1], 13);
    assert_eq!(
        NormalizedMutationCommand::decode(&prompted.encode().unwrap()).unwrap(),
        prompted
    );
}

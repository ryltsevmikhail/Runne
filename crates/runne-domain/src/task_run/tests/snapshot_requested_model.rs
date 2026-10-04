#[test]
fn closed_snapshot_preserves_requested_model_and_decodes_v2_without_one() {
    let base = create_aggregate();
    let mut aggregate = base.clone();
    aggregate
        .apply_payload(&TaskRunEvent::TaskRunSubmitted {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            input: TaskRunInput::new("prompt".to_owned())
                .unwrap()
                .with_requested_model("model-a".to_owned())
                .unwrap(),
        })
        .unwrap();

    let encoded = aggregate.snapshot_v1().encode().unwrap();
    let decoded = TaskRunSnapshotV1::decode(&encoded).unwrap();
    assert_eq!(decoded, aggregate.snapshot_v1());
    assert_eq!(decoded.input().unwrap().requested_model(), Some("model-a"));

    let mut no_model = base;
    no_model
        .apply_payload(&TaskRunEvent::TaskRunSubmitted {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            input: TaskRunInput::new("prompt".to_owned()).unwrap(),
        })
        .unwrap();
    let legacy_v2 = no_model.snapshot_v1().encode().unwrap();
    assert_eq!(legacy_v2[0], 2);
    let decoded_v2 = TaskRunSnapshotV1::decode(&legacy_v2).unwrap();
    assert_eq!(decoded_v2.input().unwrap().requested_model(), None);
}

#[test]
fn selected_profile_uses_additive_snapshot_v4_and_round_trips_exact_tuple() {
    let mut aggregate = create_aggregate();
    let selected = SelectedProviderProfile::new("profile/a".into(), [7; 32]).unwrap();
    aggregate
        .apply_payload(&TaskRunEvent::TaskRunSubmitted {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            input: TaskRunInput::new("prompt".into())
                .unwrap()
                .with_selected_profile(selected.clone())
                .unwrap(),
        })
        .unwrap();
    let encoded = aggregate.snapshot_v1().encode().unwrap();
    assert_eq!(encoded[0], 4);
    let decoded = TaskRunSnapshotV1::decode(&encoded).unwrap();
    assert_eq!(decoded.input().unwrap().selected_profile(), Some(&selected));
    assert_eq!(decoded, aggregate.snapshot_v1());
}

#[test]
fn local_command_uses_snapshot_v5_and_rejects_unknown_executable_origin() {
    let mut aggregate = create_aggregate();
    let executable = TaskRunExecutable::system_program("rustc".into()).unwrap();
    let command = TaskRunLocalCommand::new(
        executable.clone(),
        "src".into(),
        vec!["rustc".into(), "--version".into()],
        vec![],
    )
    .unwrap();
    aggregate
        .apply_payload(&TaskRunEvent::TaskRunSubmitted {
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            input: TaskRunInput::new("describe this command".into())
                .unwrap()
                .with_local_command(command)
                .unwrap(),
        })
        .unwrap();
    let encoded = aggregate.snapshot_v1().encode().unwrap();
    assert_eq!(encoded[0], 5);
    let decoded = TaskRunSnapshotV1::decode(&encoded).unwrap();
    assert_eq!(
        decoded
            .input()
            .unwrap()
            .local_command()
            .unwrap()
            .executable(),
        &executable
    );
    assert_eq!(decoded, aggregate.snapshot_v1());

    let mut malformed = encoded;
    let marker = b"rustc";
    let start = malformed
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    malformed[start - 5] = 9;
    assert!(TaskRunSnapshotV1::decode(&malformed).is_err());
}

#[test]
fn local_command_submit_uses_v5_and_round_trips_exact_intent() {
    let command = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/check".into()).unwrap(),
        "src".into(),
        vec!["check".into(), "--all".into()],
        vec![("LANG".into(), "C".into())],
    )
    .unwrap();
    let event = TaskRunEvent::TaskRunSubmitted {
        conversation_id: CONV_ID.parse().unwrap(),
        workspace_id: WS_ID.parse().unwrap(),
        input: runne_domain::task_run::TaskRunInput::new("describe this check".into())
            .unwrap()
            .with_local_command(command)
            .unwrap(),
    };
    let codec = TaskRunEventCodec;
    let bytes = codec.encode(&event).unwrap();
    assert_eq!(&bytes[..2], &5u16.to_be_bytes());
    assert_eq!(codec.decode(&bytes).unwrap(), event);
}

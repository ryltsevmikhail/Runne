#[test]
fn selected_profile_uses_v3_event_and_preserves_v1_v2_encodings() {
    let codec = TaskRunEventCodec;
    let profile =
        runne_domain::task_run::SelectedProviderProfile::new("profile/a".into(), [4; 32]).unwrap();
    let event = TaskRunEvent::TaskRunSubmitted {
        conversation_id: CONV_ID.parse().unwrap(),
        workspace_id: WS_ID.parse().unwrap(),
        input: runne_domain::task_run::TaskRunInput::new("prompt".into())
            .unwrap()
            .with_selected_profile(profile)
            .unwrap(),
    };
    let bytes = codec.encode(&event).unwrap();
    assert_eq!(&bytes[..2], &3u16.to_be_bytes());
    assert_eq!(codec.decode(&bytes).unwrap(), event);
}

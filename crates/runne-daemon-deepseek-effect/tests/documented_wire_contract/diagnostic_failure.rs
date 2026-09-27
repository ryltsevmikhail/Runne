#[tokio::test]
async fn adapter_fails_closed_on_chat_done_terminal_frame() {
    let server = DocumentedServer::start(WireResponse::ChatDone).await;
    let (_, events, _, _diagnostics) = dispatch_on(server).await;
    assert_eq!(events, Err(DispatchError::MaybeDispatched));
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(_diagnostics.iter().any(|item| matches!(
        item,
        runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic::DecodeFailed(_)
    )));
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(!format!("{_diagnostics:?}").contains("BODY_MARKER_NOT_FOR_DIAGNOSTICS"));
}

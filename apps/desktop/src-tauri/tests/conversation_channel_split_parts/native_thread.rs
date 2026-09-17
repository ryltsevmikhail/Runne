#[test]
fn subscription_from_native_thread_uses_the_desktop_executor() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let manager = ConversationSubscriptionManager::new();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let channel = Channel::new(move |_| {
        let _ = sender.try_send(());
        Ok(())
    });
    let source = Arc::new(ScriptedSource {
        updates: Vec::new(),
        terminal: Terminal::Unavailable,
    });
    manager.subscribe(source, PROJECT_ID, "native-thread", channel)
        .expect("subscription admitted outside Tokio");
    receiver.recv_timeout(Duration::from_secs(3)).expect("terminal event delivered");
    manager.shutdown();
}

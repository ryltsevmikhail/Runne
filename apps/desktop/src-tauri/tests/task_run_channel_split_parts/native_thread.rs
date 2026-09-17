#[test]
fn subscription_and_window_cancellation_from_native_thread_use_desktop_executor() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let manager = TaskRunSubscriptionManager::new();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let channel = Channel::new(move |_| {
        let _ = sender.try_send(());
        Ok(())
    });
    manager
        .subscribe(
            Arc::new(Source(Outcome::Pending)),
            TASK_RUN_ID,
            "native-thread",
            channel,
        )
        .expect("subscription admitted outside Tokio");
    receiver
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("timeline event delivered");
    manager.cancel_window("native-thread");
    manager.shutdown();
}

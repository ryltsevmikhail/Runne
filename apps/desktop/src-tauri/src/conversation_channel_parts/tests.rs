mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnected_updates_after_source_completion_does_not_repoll_join_handle() {
        let manager = Arc::new(ManagerInner {
            registry: Mutex::new(Registry::default()),
        });
        let sent_events = Arc::new(AtomicUsize::new(0));
        let sent_events_in_callback = Arc::clone(&sent_events);
        let channel = Channel::new(move |_| {
            sent_events_in_callback.fetch_add(1, Ordering::AcqRel);
            Ok(())
        });
        let (updates_tx, updates_rx) = mpsc::channel(1);
        drop(updates_tx);
        let source_task = tokio::spawn(async { Err(AppCoreError::RuntimeUnavailable) });
        while !source_task.is_finished() {
            tokio::task::yield_now().await;
        }

        run_subscription(
            Arc::downgrade(&manager),
            "test-subscription".to_owned(),
            Arc::new(SubscriptionControl::new()),
            channel,
            updates_rx,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
            source_task,
        )
        .await;

        assert_eq!(sent_events.load(Ordering::Acquire), 1);
    }
}

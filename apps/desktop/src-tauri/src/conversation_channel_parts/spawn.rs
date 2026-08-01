fn remove_subscription(
    registry: &mut Registry,
    subscription_id: &str,
) -> Option<Arc<SubscriptionControl>> {
    let record = registry.subscriptions.remove(subscription_id)?;
    registry
        .by_pair
        .remove(&(record.window_label, record.project_id));
    Some(record.control)
}

fn spawn_subscription<S>(
    manager: Weak<ManagerInner>,
    subscription_id: String,
    source: Arc<S>,
    project_id: i64,
    control: Arc<SubscriptionControl>,
    on_update: Channel<ConversationChannelEvent>,
) where
    S: ConversationUpdateSource,
{
    let (updates_tx, updates_rx) = mpsc::channel(MAX_QUEUED_UPDATES);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let overflowed = Arc::new(AtomicBool::new(false));
    let overflow_changed = Arc::new(Notify::new());
    let callback_bytes = Arc::clone(&queued_bytes);
    let callback_overflowed = Arc::clone(&overflowed);
    let callback_overflow_changed = Arc::clone(&overflow_changed);
    let source_task = tokio::spawn(async move {
        source
            .subscribe(
                project_id,
                Box::new(move |update| {
                    let event = ConversationChannelEvent::update(update);
                    let Ok(bytes) = serde_json::to_vec(&event).map(|value| value.len()) else {
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                        return;
                    };
                    if !reserve_bytes(&callback_bytes, bytes) {
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                        return;
                    }
                    if updates_tx.try_send(QueuedUpdate { event, bytes }).is_err() {
                        callback_bytes.fetch_sub(bytes, Ordering::AcqRel);
                        mark_overflow(&callback_overflowed, &callback_overflow_changed);
                    }
                }),
            )
            .await
    });
    tokio::spawn(run_subscription(
        manager,
        subscription_id,
        control,
        on_update,
        updates_rx,
        queued_bytes,
        overflowed,
        overflow_changed,
        source_task,
    ));
}

fn remove_subscription(
    registry: &mut Registry,
    subscription_id: &str,
) -> Option<Arc<SubscriptionControl>> {
    let record = registry.subscriptions.remove(subscription_id)?;
    registry
        .by_pair
        .remove(&(record.window_label, record.conversation_key));
    Some(record.control)
}

fn spawn_subscription<S>(
    manager: Weak<ManagerInner>,
    subscription_id: String,
    source: Arc<S>,
    target: ConversationSubscriptionTarget,
    control: Arc<SubscriptionControl>,
    on_update: Channel<ConversationChannelEvent>,
) where
    S: ConversationUpdateSource,
{
    let runtime = tokio::runtime::Handle::try_current()
        .unwrap_or_else(|_| tauri::async_runtime::handle().inner().clone());
    let (updates_tx, updates_rx) = mpsc::channel(MAX_QUEUED_UPDATES);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let overflowed = Arc::new(AtomicBool::new(false));
    let overflow_changed = Arc::new(Notify::new());
    let callback_bytes = Arc::clone(&queued_bytes);
    let callback_overflowed = Arc::clone(&overflowed);
    let callback_overflow_changed = Arc::clone(&overflow_changed);
    let source_task = runtime.spawn(async move {
        let callback = Box::new(move |update| {
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
        });
        match target {
            ConversationSubscriptionTarget::Project(project_id) => {
                source.subscribe(project_id, callback).await
            }
            ConversationSubscriptionTarget::Workspace(workspace_id) => {
                source.subscribe_workspace(workspace_id, callback).await
            }
            ConversationSubscriptionTarget::TextOnly => source.subscribe_text_only(callback).await,
        }
    });
    runtime.spawn(run_subscription(
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

#[allow(clippy::too_many_arguments)]
async fn run_subscription(
    registry: Weak<Mutex<Registry>>,
    subscription_id: String,
    control: Arc<SubscriptionControl>,
    channel: Channel<TaskRunChannelEvent>,
    mut updates_rx: mpsc::Receiver<QueuedUpdate>,
    queued_bytes: Arc<AtomicUsize>,
    overflowed: Arc<AtomicBool>,
    overflow_changed: Arc<Notify>,
    mut source_task: JoinHandle<Result<(), AppCoreError>>,
) {
    let mut source_finished = false;
    let mut source_error = None;
    let mut in_flight = None;
    let mut terminal_error = None;
    loop {
        if control.is_cancelled() {
            break;
        }
        if overflowed.load(Ordering::Acquire) {
            terminal_error = Some(TaskRunChannelErrorCode::TaskRunSubscriptionUnavailable);
            break;
        }
        if let Some((revision, sent_at)) = in_flight {
            tokio::select! {
                () = control.changed.notified() => { if !control.is_in_flight(revision) { in_flight = None; } }
                () = overflow_changed.notified() => {}
                result = &mut source_task, if !source_finished => { source_finished = true; source_error = Some(map_source_result(result)); }
                () = tokio::time::sleep_until(sent_at + ACK_TIMEOUT) => { terminal_error = Some(TaskRunChannelErrorCode::TaskRunSubscriptionUnavailable); break; }
            }
            continue;
        }
        if source_finished {
            match updates_rx.try_recv() {
                Ok(update) => {
                    queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                    if !send_update(&control, &channel, update.event, &mut in_flight) { break; }
                }
                Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if let Some(error) = source_error.take() { let _ = channel.send(TaskRunChannelEvent::Error { code: error }); }
                    break;
                }
            }
            continue;
        }
        tokio::select! {
            () = control.changed.notified() => {}
            () = overflow_changed.notified() => {}
            result = &mut source_task => { source_finished = true; source_error = Some(map_source_result(result)); }
            update = updates_rx.recv() => if let Some(update) = update {
                queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                if !send_update(&control, &channel, update.event, &mut in_flight) { break; }
            }
        }
    }
    if !source_finished {
        source_task.abort();
        let _ = source_task.await;
    }
    if let Some(error) = terminal_error {
        let _ = channel.send(TaskRunChannelEvent::Error { code: error });
    }
    release_finished(&registry, &subscription_id);
}

fn spawn_subscription<S>(
    registry: Weak<Mutex<Registry>>,
    subscription_id: String,
    source: Arc<S>,
    task_run_id: String,
    control: Arc<SubscriptionControl>,
    channel: Channel<TaskRunChannelEvent>,
    start_rx: tokio::sync::oneshot::Receiver<()>,
) -> JoinHandle<()>
where
    S: TaskRunUpdateSource,
{
    let runtime = tokio::runtime::Handle::try_current()
        .unwrap_or_else(|_| tauri::async_runtime::handle().inner().clone());
    runtime.spawn(async move {
        if start_rx.await.is_err() { return; }
        let (updates_tx, updates_rx) = mpsc::channel(MAX_QUEUED_UPDATES);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let overflowed = Arc::new(AtomicBool::new(false));
        let overflow_changed = Arc::new(Notify::new());
        let callback_bytes = Arc::clone(&queued_bytes);
        let callback_overflowed = Arc::clone(&overflowed);
        let callback_changed = Arc::clone(&overflow_changed);
        let source_task = tokio::spawn(async move {
            source.subscribe(task_run_id, Box::new(move |update| {
                let event = TaskRunChannelEvent::Update { update };
                let Ok(bytes) = serde_json::to_vec(&event).map(|value| value.len()) else { mark_overflow(&callback_overflowed, &callback_changed); return; };
                if !reserve_bytes(&callback_bytes, bytes) { mark_overflow(&callback_overflowed, &callback_changed); return; }
                if updates_tx.try_send(QueuedUpdate { event, bytes }).is_err() {
                    callback_bytes.fetch_sub(bytes, Ordering::AcqRel);
                    mark_overflow(&callback_overflowed, &callback_changed);
                }
            })).await
        });
        run_subscription(registry, subscription_id, control, channel, updates_rx, queued_bytes, overflowed, overflow_changed, source_task).await;
    })
}

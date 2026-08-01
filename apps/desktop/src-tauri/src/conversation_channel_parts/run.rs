struct QueuedUpdate {
    event: ConversationChannelEvent,
    bytes: usize,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_subscription(
    manager: Weak<ManagerInner>,
    subscription_id: String,
    control: Arc<SubscriptionControl>,
    on_update: Channel<ConversationChannelEvent>,
    mut updates_rx: mpsc::Receiver<QueuedUpdate>,
    queued_bytes: Arc<AtomicUsize>,
    overflowed: Arc<AtomicBool>,
    overflow_changed: Arc<Notify>,
    mut source_task: JoinHandle<Result<(), AppCoreError>>,
) {
    let mut source_error = None;
    let mut in_flight = None;
    let mut terminal_error = None;
    loop {
        if control.is_cancelled() {
            break;
        }
        if overflowed.load(Ordering::Acquire) {
            terminal_error =
                Some(ConversationChannelErrorCode::ConversationSubscriptionUnavailable);
            break;
        }

        if let Some((revision, sent_at)) = in_flight {
            tokio::select! {
                () = control.changed.notified() => {
                    if control.is_cancelled() {
                        break;
                    }
                    if !control.is_in_flight(revision) {
                        in_flight = None;
                    }
                }
                () = overflow_changed.notified() => {}
                result = &mut source_task, if source_error.is_none() => {
                    source_error = Some(map_source_result(result));
                }
                () = tokio::time::sleep_until(sent_at + ACK_TIMEOUT) => {
                    terminal_error =
                        Some(ConversationChannelErrorCode::ConversationSubscriptionUnavailable);
                    break;
                }
            }
            continue;
        }

        if source_error.is_some() {
            match updates_rx.try_recv() {
                Ok(update) => {
                    queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                    if !send_update(&control, &on_update, update.event, &mut in_flight) {
                        break;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    let error = source_error.take().unwrap_or(
                        ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
                    );
                    let _ = on_update.send(ConversationChannelEvent::error(error));
                    break;
                }
            }
        }

        tokio::select! {
            () = control.changed.notified() => {}
            () = overflow_changed.notified() => {}
            result = &mut source_task => {
                source_error = Some(map_source_result(result));
            }
            update = updates_rx.recv() => {
                if let Some(update) = update {
                    queued_bytes.fetch_sub(update.bytes, Ordering::AcqRel);
                    if !send_update(&control, &on_update, update.event, &mut in_flight) {
                        break;
                    }
                }
            }
        }
    }

    if source_error.is_none() {
        source_task.abort();
        let _ = source_task.await;
    }
    if let Some(error) = terminal_error {
        let _ = on_update.send(ConversationChannelEvent::error(error));
    }
    release_finished(&manager, &subscription_id);
}

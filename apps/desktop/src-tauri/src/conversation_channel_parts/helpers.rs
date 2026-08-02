fn send_update(
    control: &SubscriptionControl,
    on_update: &Channel<ConversationChannelEvent>,
    event: ConversationChannelEvent,
    in_flight: &mut Option<(u64, Instant)>,
) -> bool {
    let Some(revision) = event.projection_revision() else {
        return false;
    };
    if !control.set_in_flight(revision) {
        return false;
    }
    if on_update.send(event).is_err() {
        control.cancel();
        return false;
    }
    *in_flight = Some((revision, Instant::now()));
    true
}

fn map_source_result(
    result: Result<Result<(), AppCoreError>, tokio::task::JoinError>,
) -> ConversationChannelErrorCode {
    match result {
        Ok(Err(error)) => ConversationChannelErrorCode::from_app_core(&error),
        Ok(Ok(())) | Err(_) => ConversationChannelErrorCode::ConversationSubscriptionUnavailable,
    }
}

fn reserve_bytes(queued_bytes: &AtomicUsize, bytes: usize) -> bool {
    let mut current = queued_bytes.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if next > MAX_QUEUED_BYTES {
            return false;
        }
        match queued_bytes.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn mark_overflow(overflowed: &AtomicBool, changed: &Notify) {
    overflowed.store(true, Ordering::Release);
    changed.notify_one();
}

fn release_finished(manager: &Weak<ManagerInner>, subscription_id: &str) {
    let Some(manager) = manager.upgrade() else {
        return;
    };
    let Ok(mut registry) = manager.registry.lock() else {
        return;
    };
    let _ = remove_subscription(&mut registry, subscription_id);
}

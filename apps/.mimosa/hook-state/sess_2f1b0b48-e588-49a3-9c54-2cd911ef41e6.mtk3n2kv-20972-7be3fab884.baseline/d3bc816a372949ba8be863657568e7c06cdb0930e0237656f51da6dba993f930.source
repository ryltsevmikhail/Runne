use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct QueuedUpdate {
    event: TaskRunChannelEvent,
    bytes: usize,
}

fn send_update(
    control: &SubscriptionControl,
    channel: &Channel<TaskRunChannelEvent>,
    event: TaskRunChannelEvent,
    in_flight: &mut Option<(u64, tokio::time::Instant)>,
) -> bool {
    let TaskRunChannelEvent::Update { update } = &event else {
        return false;
    };
    let revision = update.projection_revision;
    if !control.set_in_flight(revision) || channel.send(event).is_err() {
        control.cancel();
        return false;
    }
    *in_flight = Some((revision, tokio::time::Instant::now()));
    true
}

fn map_source_result(
    result: Result<Result<(), AppCoreError>, tokio::task::JoinError>,
) -> TaskRunChannelErrorCode {
    match result {
        Ok(Ok(())) | Err(_) => TaskRunChannelErrorCode::TaskRunSubscriptionUnavailable,
        Ok(Err(error)) => TaskRunChannelErrorCode::from_app_core(&error),
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

fn release_finished(registry: &Weak<Mutex<Registry>>, subscription_id: &str) {
    let Some(registry) = registry.upgrade() else {
        return;
    };
    if let Ok(mut registry) = registry.lock() {
        let _ = registry.subscriptions.remove(subscription_id);
    }
}

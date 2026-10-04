use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::oneshot;

struct PendingAck {
    token: u64,
    arrived: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

static PENDING_ACKS: OnceLock<Mutex<HashMap<String, PendingAck>>> = OnceLock::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelAckBarrierError {
    DuplicateTaskRun,
    RegistryPoisoned,
    AlreadyWaited,
    HandlerClosed,
}

/// Test-only barrier for one exact TaskRun cancellation acknowledgement.
pub struct CancelAckBarrier {
    taskrun_id: String,
    token: u64,
    arrived: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
}

impl CancelAckBarrier {
    /// Waits until the HTTP handler has committed cancellation and is holding
    /// the response immediately before acknowledgement.
    pub async fn wait_until_held(&mut self) -> Result<(), CancelAckBarrierError> {
        self.arrived
            .take()
            .ok_or(CancelAckBarrierError::AlreadyWaited)?
            .await
            .map_err(|_| CancelAckBarrierError::HandlerClosed)
    }

    /// Releases the held HTTP response. Dropping the barrier also releases it.
    pub fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for CancelAckBarrier {
    fn drop(&mut self) {
        if let Ok(mut pending) = registry().lock()
            && pending
                .get(&self.taskrun_id)
                .is_some_and(|entry| entry.token == self.token)
        {
            pending.remove(&self.taskrun_id);
        }
        self.release();
    }
}

/// Arms a barrier for one exact taskrun ID; unrelated concurrent tests pass.
pub fn hold_cancel_ack(
    taskrun_id: impl Into<String>,
) -> Result<CancelAckBarrier, CancelAckBarrierError> {
    let (arrived_tx, arrived_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let mut pending = registry()
        .lock()
        .map_err(|_| CancelAckBarrierError::RegistryPoisoned)?;
    let taskrun_id = taskrun_id.into();
    if pending.contains_key(&taskrun_id) {
        return Err(CancelAckBarrierError::DuplicateTaskRun);
    }
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    pending.insert(
        taskrun_id.clone(),
        PendingAck {
            token,
            arrived: arrived_tx,
            release: release_rx,
        },
    );
    Ok(CancelAckBarrier {
        taskrun_id,
        token,
        arrived: Some(arrived_rx),
        release: Some(release_tx),
    })
}

pub(super) async fn pause_cancel_ack(taskrun_id: &str) {
    let pending = registry()
        .lock()
        .ok()
        .and_then(|mut pending| pending.remove(taskrun_id));
    if let Some(pending) = pending {
        let _ = pending.arrived.send(());
        let _ = tokio::time::timeout(Duration::from_secs(10), pending.release).await;
    }
}

fn registry() -> &'static Mutex<HashMap<String, PendingAck>> {
    PENDING_ACKS.get_or_init(|| Mutex::new(HashMap::new()))
}

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

use super::spawn_pre_fence_enrollment_owner;

#[tokio::test]
async fn cancelled_command_cannot_cancel_the_cleanup_supervisor() {
    for cancel_at in 0..3 {
        let stopped = Arc::new(AtomicUsize::new(0));
        let degraded = Arc::new(AtomicUsize::new(0));
        let stop = Arc::clone(&stopped);
        let degrade = Arc::clone(&degraded);
        let (events_tx, events_rx) = mpsc::channel();
        let (first_tx, first_rx) = mpsc::sync_channel(0);
        let (second_tx, second_rx) = mpsc::sync_channel(0);
        let (result, completion) = spawn_pre_fence_enrollment_owner(
            move || async move {
                tauri::async_runtime::spawn_blocking(move || {
                    events_tx.send(1).unwrap();
                    first_rx.recv().unwrap();
                    events_tx.send(2).unwrap();
                    second_rx.recv().unwrap();
                    Err::<(), ()>(())
                })
                .await
                .map_err(|_| ())?
            },
            move || async move {
                stop.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                degrade.fetch_add(1, Ordering::SeqCst);
            },
            || (),
        )
        .expect("watcher spawn");
        let command = tokio::spawn(result);
        if cancel_at == 0 {
            command.abort();
        }
        assert_eq!(events_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        if cancel_at == 1 {
            command.abort();
        }
        first_tx.send(()).unwrap();
        assert_eq!(events_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        if cancel_at == 2 {
            command.abort();
        }
        second_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .expect("supervisor timeout")
            .expect("supervisor completion");
        let _ = command.await;
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert_eq!(degraded.load(Ordering::SeqCst), 1);
    }
}

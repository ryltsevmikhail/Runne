use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

use super::{
    PostFenceEnrollmentDependencies, run_post_fence_branches, spawn_cleanup_supervised_transcript,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    RotatedSession,
    UpdaterRevalidation,
    RegistryExhaustion,
}

struct InjectedPostFenceDependencies {
    fault: Fault,
    stages: Arc<[AtomicUsize; 3]>,
}

impl PostFenceEnrollmentDependencies for InjectedPostFenceDependencies {
    type Output = ();
    type Error = Fault;

    fn require_rotated_session(&mut self) -> Result<(), Self::Error> {
        self.stages[0].fetch_add(1, Ordering::SeqCst);
        (self.fault != Fault::RotatedSession)
            .then_some(())
            .ok_or(self.fault)
    }

    fn revalidate_updater(&mut self) -> Result<(), Self::Error> {
        self.stages[1].fetch_add(1, Ordering::SeqCst);
        (self.fault != Fault::UpdaterRevalidation)
            .then_some(())
            .ok_or(self.fault)
    }

    fn admit_registry(self) -> Result<Self::Output, Self::Error> {
        self.stages[2].fetch_add(1, Ordering::SeqCst);
        (self.fault != Fault::RegistryExhaustion)
            .then_some(())
            .ok_or(self.fault)
    }
}

#[tokio::test]
async fn actual_post_fence_failure_branches_cleanup_once_before_writer() {
    for fault in [
        Fault::RotatedSession,
        Fault::UpdaterRevalidation,
        Fault::RegistryExhaustion,
    ] {
        let stages = Arc::new([
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ]);
        let stopped = Arc::new(AtomicUsize::new(0));
        let degraded = Arc::new(AtomicUsize::new(0));
        let writer = Arc::new(AtomicUsize::new(0));
        let stop = Arc::clone(&stopped);
        let degrade = Arc::clone(&degraded);
        let result = run_post_fence_branches(
            InjectedPostFenceDependencies {
                fault,
                stages: Arc::clone(&stages),
            },
            move || async move {
                stop.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                degrade.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        if result.is_ok() {
            writer.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(result, Err(fault));
        let expected = match fault {
            Fault::RotatedSession => [1, 0, 0],
            Fault::UpdaterRevalidation => [1, 1, 0],
            Fault::RegistryExhaustion => [1, 1, 1],
        };
        assert_eq!(
            stages.each_ref().map(|value| value.load(Ordering::SeqCst)),
            expected
        );
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert_eq!(degraded.load(Ordering::SeqCst), 1);
        assert_eq!(writer.load(Ordering::SeqCst), 0);
    }
}

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
        let (result, completion) = spawn_cleanup_supervised_transcript(
            move || {
                events_tx.send(1).unwrap();
                first_rx.recv().unwrap();
                events_tx.send(2).unwrap();
                second_rx.recv().unwrap();
                Err(())
            },
            move || async move {
                stop.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                degrade.fetch_add(1, Ordering::SeqCst);
            },
        );
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
        tokio::time::timeout(Duration::from_secs(1), completion)
            .await
            .expect("supervisor timeout")
            .expect("supervisor completion");
        let _ = command.await;
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert_eq!(degraded.load(Ordering::SeqCst), 1);
    }
}

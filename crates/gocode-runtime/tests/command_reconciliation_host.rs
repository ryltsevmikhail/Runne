use gocode_api::{
    ApiPrincipalId, CommandReconciliationContext, CommandReconciliationHostError,
    CommandReconciliationHostPort, CommandReconciliationWitness,
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::sync::oneshot;

use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence, CommandReconciliationRepository,
    CommandReconciliationRepositoryError,
};
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId};
use gocode_runtime::RuntimeCommandReconciliationHost;

#[derive(Clone)]
struct Repository;
impl CommandReconciliationRepository for Repository {
    fn reconcile_command(
        &self,
        _: &CommandReconciliationContext,
        _: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationEvidence, CommandReconciliationRepositoryError> {
        Ok(CommandReconciliationEvidence::NotCommitted)
    }
}

#[derive(Clone)]
struct BlockingRepository {
    gate: Arc<BlockingGate>,
}

struct BlockingGate {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    released: Mutex<bool>,
    release: Condvar,
}

impl BlockingGate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

impl CommandReconciliationRepository for BlockingRepository {
    fn reconcile_command(
        &self,
        _: &CommandReconciliationContext,
        _: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationEvidence, CommandReconciliationRepositoryError> {
        if let Some(entered) = self.gate.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
            let mut released = self.gate.released.lock().unwrap();
            while !*released {
                released = self.gate.release.wait(released).unwrap();
            }
        }
        Ok(CommandReconciliationEvidence::NotCommitted)
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn context() -> CommandReconciliationContext {
    CommandReconciliationContext::new(
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d901"
            .parse::<CommandId>()
            .unwrap(),
        IdempotencyKey::new("key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    )
}

fn witness() -> CommandReconciliationWitness {
    CommandReconciliationWitness::archive_project(
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d902"
            .parse::<ProjectId>()
            .unwrap(),
        1,
    )
}

#[tokio::test]
async fn host_returns_read_only_application_disposition() {
    let host = RuntimeCommandReconciliationHost::new(Repository);
    let disposition = host.reconcile_command(context(), witness()).await.unwrap();
    assert!(disposition.is_not_committed_retryable());
    assert_ne!(
        CommandReconciliationHostError::Backpressure,
        CommandReconciliationHostError::Unavailable
    );
}

#[tokio::test]
async fn host_rejects_requests_when_the_bounded_worker_queue_is_full() {
    let (entered, observed) = oneshot::channel();
    let gate = Arc::new(BlockingGate {
        entered: Mutex::new(Some(entered)),
        released: Mutex::new(false),
        release: Condvar::new(),
    });
    let host = Arc::new(RuntimeCommandReconciliationHost::with_capacity(
        BlockingRepository { gate: gate.clone() },
        1,
    ));
    let first_host = host.clone();
    let first =
        tokio::spawn(async move { first_host.reconcile_command(context(), witness()).await });
    observed.await.unwrap();
    let second = host.reconcile_command(context(), witness());
    tokio::pin!(second);
    assert!(matches!(poll_once(second.as_mut()), Poll::Pending));
    assert_eq!(
        host.reconcile_command(context(), witness()).await,
        Err(CommandReconciliationHostError::Backpressure)
    );
    gate.release();
    assert!(first.await.unwrap().is_ok());
    assert!(second.await.is_ok());
}

#[tokio::test]
async fn host_fails_closed_after_its_worker_stops() {
    let host = RuntimeCommandReconciliationHost::new(Repository);
    host.shutdown().await;
    assert_eq!(
        host.reconcile_command(context(), witness()).await,
        Err(CommandReconciliationHostError::Unavailable)
    );
}

#[path = "provider_execution_recovery.rs"]
mod recovery;
#[path = "operational_telemetry_security.rs"]
mod security;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gocode_application::provider::{
    ProviderExecutionStore, ProviderRecoveryObserver, ProviderRecoveryObserverError,
};
use gocode_runtime::provider_execution::{
    ProviderTerminalApplicationError, ProviderTerminalOutboxApplication,
    ProviderTerminalPersistence, RuntimeProviderExecutionError,
};
use gocode_store::provider::SqliteProviderExecutionStore;

struct RecordingApplication {
    result: Result<[u8; 32], ProviderTerminalApplicationError>,
}

impl ProviderTerminalOutboxApplication for RecordingApplication {
    fn complete_provider_terminal(
        &self,
        _record: &gocode_application::provider::ProviderTerminalOutboxRecord,
        _output: &[u8],
    ) -> Result<[u8; 32], ProviderTerminalApplicationError> {
        self.result
    }
}

struct RecordingRecoveryObserver {
    store: Arc<SqliteProviderExecutionStore>,
    expected_outbox_id: [u8; 16],
    acknowledgements: Mutex<Vec<[u8; 16]>>,
    calls: AtomicUsize,
    fail: bool,
}

impl RecordingRecoveryObserver {
    fn new(
        store: Arc<SqliteProviderExecutionStore>,
        expected_outbox_id: [u8; 16],
        fail: bool,
    ) -> Self {
        Self {
            store,
            expected_outbox_id,
            acknowledgements: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            fail,
        }
    }
}

impl ProviderRecoveryObserver for RecordingRecoveryObserver {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(self.store.pending_terminal_outbox().unwrap().is_empty());
        self.acknowledgements
            .lock()
            .unwrap()
            .push(self.expected_outbox_id);
        if self.fail {
            Err(ProviderRecoveryObserverError::Unavailable)
        } else {
            Ok(())
        }
    }
}

async fn prepare_terminal_output(fixture: &recovery::Fixture, keyring: &recovery::MemoryKeyring) {
    let writer = recovery::runtime(keyring, fixture.execution.as_ref());
    writer.create_and_activate_key([1; 16], 7, 1).unwrap();
    recovery::poll_events(
        &writer,
        fixture,
        recovery::successful_events("recovered-terminal-output"),
    )
    .await;
    writer
        .finalize_terminal_output(&recovery::context(fixture))
        .unwrap();
}

fn pending_outbox_id<S>(
    runtime: &gocode_runtime::provider_execution::RuntimeProviderExecution<
        '_,
        recovery::MemoryKeyring,
        S,
        recovery::FixedPricing,
    >,
) -> [u8; 16]
where
    S: ProviderExecutionStore + ProviderTerminalPersistence,
{
    runtime.recover_pending_terminal_outputs().unwrap()[0]
        .record()
        .outbox_id
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_acknowledges_before_one_ignored_observer_call() {
    let fixture = recovery::fixture();
    let keyring = recovery::MemoryKeyring::default();
    prepare_terminal_output(&fixture, &keyring).await;
    let runtime = recovery::runtime(&keyring, fixture.execution.as_ref());
    let outbox_id = pending_outbox_id(&runtime);
    let application = RecordingApplication {
        result: Ok([7; 32]),
    };
    let observer = RecordingRecoveryObserver::new(Arc::clone(&fixture.execution), outbox_id, false);

    assert_eq!(
        runtime.apply_pending_terminal_outputs(&application, &observer),
        Ok(1)
    );
    assert_eq!(
        observer.acknowledgements.lock().unwrap().as_slice(),
        [outbox_id]
    );
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_observer_call_matrix_excludes_unsuccessful_acknowledgements() {
    for result in [
        Err(ProviderTerminalApplicationError::Unavailable),
        Err(ProviderTerminalApplicationError::Conflict),
        Ok([0; 32]),
    ] {
        let fixture = recovery::fixture();
        let keyring = recovery::MemoryKeyring::default();
        prepare_terminal_output(&fixture, &keyring).await;
        let runtime = recovery::runtime(&keyring, fixture.execution.as_ref());
        let outbox_id = pending_outbox_id(&runtime);
        let observer =
            RecordingRecoveryObserver::new(Arc::clone(&fixture.execution), outbox_id, false);

        assert!(
            runtime
                .apply_pending_terminal_outputs(&RecordingApplication { result }, &observer)
                .is_err()
        );
        assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_ack_failure_does_not_call_observer() {
    let fixture = recovery::fixture();
    let keyring = recovery::MemoryKeyring::default();
    prepare_terminal_output(&fixture, &keyring).await;
    let failing = recovery::FailFirstAcknowledgementStore {
        inner: Arc::clone(&fixture.execution),
        fail_acknowledgement: std::sync::atomic::AtomicBool::new(true),
    };
    let runtime = recovery::runtime(&keyring, &failing);
    let outbox_id = pending_outbox_id(&runtime);
    let observer = RecordingRecoveryObserver::new(Arc::clone(&fixture.execution), outbox_id, false);

    assert_eq!(
        runtime.apply_pending_terminal_outputs(
            &RecordingApplication {
                result: Ok([7; 32])
            },
            &observer
        ),
        Err(RuntimeProviderExecutionError::PersistenceUnavailable)
    );
    assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn foreground_terminal_apply_never_calls_recovery_observer() {
    let fixture = recovery::fixture();
    let keyring = recovery::MemoryKeyring::default();
    prepare_terminal_output(&fixture, &keyring).await;
    let runtime = recovery::runtime(&keyring, fixture.execution.as_ref());
    let outbox_id = pending_outbox_id(&runtime);
    let observer = RecordingRecoveryObserver::new(Arc::clone(&fixture.execution), outbox_id, false);

    assert_eq!(
        runtime.apply_terminal_output_for_attempt(
            fixture.attempt_id,
            &RecordingApplication {
                result: Ok([7; 32])
            },
        ),
        Ok(true)
    );
    assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_keeps_ack_success_when_observer_returns_unavailable() {
    let fixture = recovery::fixture();
    let keyring = recovery::MemoryKeyring::default();
    prepare_terminal_output(&fixture, &keyring).await;
    let runtime = recovery::runtime(&keyring, fixture.execution.as_ref());
    let outbox_id = pending_outbox_id(&runtime);
    let observer = RecordingRecoveryObserver::new(Arc::clone(&fixture.execution), outbox_id, true);

    assert_eq!(
        runtime.apply_pending_terminal_outputs(
            &RecordingApplication {
                result: Ok([7; 32])
            },
            &observer
        ),
        Ok(1)
    );
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
}

#[path = "concurrency_facts.rs"]
mod concurrency_facts;

use self::concurrency_facts::{assert_after_source, assert_before_source, source_counts};
use super::output_helpers::{OUTPUT, expected_binding, read_after_reopen};
use super::output_history::stream_history;
use super::support::{Prepared, Price};
use runne_application::ports::EventStore;
use runne_application::provider::{
    ProviderRemoteFactAuthenticator, ProviderRemoteTerminalSettlementDigestCandidate,
};
use runne_provider::{ProviderRecoveryAttemptIdentity, ProviderRecoveryError};
use runne_runtime::provider_execution::{
    ProviderRemoteTerminalSourceOutcome, RuntimeProviderRemoteIdentityCommitter,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct PauseAfterAuthentication<A> {
    delegate: Arc<A>,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl<A: ProviderRemoteFactAuthenticator> ProviderRemoteFactAuthenticator
    for PauseAfterAuthentication<A>
{
    fn authenticate_terminal_snapshot(
        &self,
        snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
        ProviderRecoveryError,
    > {
        let fact = self
            .delegate
            .authenticate_terminal_snapshot(snapshot, expected)?;
        self.entered
            .send(())
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        self.release
            .lock()
            .map_err(|_| ProviderRecoveryError::Unavailable)?
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        Ok(fact)
    }

    fn verify_terminal_settlement_digest(
        &self,
        snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
        expected: &ProviderRecoveryAttemptIdentity,
        candidate: ProviderRemoteTerminalSettlementDigestCandidate<'_>,
    ) -> Result<bool, ProviderRecoveryError> {
        self.delegate
            .verify_terminal_settlement_digest(snapshot, expected, candidate)
    }
}

#[test]
fn same_taskrun_version_remote_source_commit_is_one_effects_snapshot() {
    let prepared = completed_output_fixture_without_source();
    let before_history = stream_history(&prepared);
    assert_eq!(before_history.0, prepared.fixture.version);
    let initial_counts = source_counts(&prepared);
    assert_eq!(initial_counts, (0, 0, 0, 2, 0));

    let writer_execution = Arc::new(
        crate::validated_reopen::open_provider_execution(
            prepared.fixture.database.file.path(),
            prepared.fixture.database.identity,
        )
        .unwrap(),
    );
    let writer = Arc::new(RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(super::super::super::effect::Keyring),
        writer_execution,
    ));
    let reader_store = prepared.fixture.database.store.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = channel();
    let reader_authenticator = Arc::new(PauseAfterAuthentication {
        delegate: Arc::clone(&writer),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let reader_auth = Arc::clone(&reader_authenticator);
    let taskrun_id = prepared.fixture.taskrun_id;
    let reader = std::thread::spawn(move || {
        reader_store.load_task_run_effects_with_remote_authenticator(
            taskrun_id,
            Some(reader_auth.as_ref()),
            Some(&super::super::Resolver),
        )
    });

    let entered = entered_rx.recv_timeout(Duration::from_secs(10));
    let commit = if entered.is_ok() {
        catch_unwind(AssertUnwindSafe(|| {
            writer.commit_authenticated_remote_terminal_source(prepared.recovery, &Price)
        }))
        .ok()
    } else {
        None
    };
    let _ = release_tx.send(());
    let in_flight = reader.join().expect("bounded reader thread completes");

    assert!(entered.is_ok(), "reader reached authenticated fact barrier");
    let commit = commit.expect("writer did not panic").unwrap();
    assert_eq!(
        commit,
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let in_flight = in_flight.unwrap();
    assert_before_source(&prepared, &in_flight);
    assert_eq!(source_counts(&prepared), (1, 1, 1, 0, 2));
    super::output_workflow::assert_running_without_assistant(&prepared);
    super::output_occupation::assert_active_occupation(&prepared);

    let after = read_after_reopen(&prepared);
    assert_after_source(&prepared, &after);
    assert_eq!(
        after.effects.stream_version, in_flight.effects.stream_version,
        "Source2 changes provider side facts without changing TaskRun version"
    );
    assert_eq!(
        after.remote.as_ref().unwrap().binding,
        in_flight.remote.as_ref().unwrap().binding
    );
    assert_eq!(stream_history(&prepared), before_history);
}

fn completed_output_fixture_without_source() -> Prepared {
    let prepared = super::support::prepare(
        "remote-effects-same-version-race",
        0xd8,
        "resp_remote_effects_same_version_race",
        runne_provider::ProviderRemoteResponseStatus::Completed {
            usage: Some(runne_provider::ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some(OUTPUT),
    );
    assert_eq!(
        expected_binding(&prepared).dispatch_attempt_id,
        prepared.attempt
    );
    prepared
}

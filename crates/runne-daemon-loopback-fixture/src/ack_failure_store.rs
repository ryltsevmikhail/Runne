use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use runne_application::provider::{
    ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
    ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
    ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
};
use runne_provider::DispatchAttemptId;
use runne_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};

/// Fixture-only decorator that drops exactly the first terminal acknowledgement
/// from the first verified launch generation.
pub struct AckFailureStore<S: ?Sized> {
    inner: Arc<S>,
    launch_generation: u64,
    failed: AtomicBool,
}

impl<S: ?Sized> AckFailureStore<S> {
    pub fn new(inner: Arc<S>, launch_generation: u64) -> Self {
        Self {
            inner,
            launch_generation,
            failed: AtomicBool::new(false),
        }
    }
}

impl<S: ProviderExecutionStore + ProviderTerminalPersistence + ?Sized> ProviderExecutionStore
    for AckFailureStore<S>
{
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        self.inner.active_journal_key_binding()
    }
    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.activate_journal_key(key)
    }
    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        self.inner.journal_key_reference_count(key)
    }
    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.remove_retired_journal_key(key)
    }
    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.inner.begin_provider_poll(request)
    }
    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        self.inner.append_encrypted_event(request)
    }
    fn load_encrypted_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.inner.load_encrypted_events(attempt_id)
    }
    fn load_terminal_pricing_binding(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        self.inner.load_terminal_pricing_binding(attempt_id)
    }
    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.inner.pending_terminal_outbox()
    }
    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        if self.launch_generation == 1 && !self.failed.swap(true, Ordering::SeqCst) {
            return Err(ProviderExecutionError::StoreUnavailable);
        }
        self.inner
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
    }
    fn mark_execution_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        self.inner
            .mark_execution_uncertain(attempt_id, fencing_token)
    }
}

impl<S: ProviderExecutionStore + ProviderTerminalPersistence + ?Sized> ProviderTerminalPersistence
    for AckFailureStore<S>
{
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.inner.commit_terminal(request)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runne_application::provider::{
        ProviderExecutionError, ProviderExecutionStore, ProviderJournalAppendOutcome,
        ProviderJournalAppendRequest, ProviderJournalKeyBinding, ProviderPollRequest,
        ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
    };
    use runne_provider::DispatchAttemptId;
    use runne_runtime::provider_execution::{
        ProviderTerminalCommitRequest, ProviderTerminalPersistence,
    };

    use super::AckFailureStore;

    struct Delegate(AtomicUsize);

    impl ProviderExecutionStore for Delegate {
        fn activate_journal_key(
            &self,
            _: ProviderJournalKeyBinding,
        ) -> Result<(), ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn journal_key_reference_count(
            &self,
            _: ProviderJournalKeyBinding,
        ) -> Result<u64, ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn remove_retired_journal_key(
            &self,
            _: ProviderJournalKeyBinding,
        ) -> Result<(), ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn begin_provider_poll(
            &self,
            _: &ProviderPollRequest,
        ) -> Result<(), ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn append_encrypted_event(
            &self,
            _: &ProviderJournalAppendRequest,
        ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn load_encrypted_events(
            &self,
            _: DispatchAttemptId,
        ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn load_terminal_pricing_binding(
            &self,
            _: DispatchAttemptId,
        ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn pending_terminal_outbox(
            &self,
        ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
        fn acknowledge_terminal_outbox(
            &self,
            _: [u8; 16],
            _: [u8; 32],
        ) -> Result<(), ProviderExecutionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn mark_execution_uncertain(
            &self,
            _: DispatchAttemptId,
            _: u64,
        ) -> Result<(), ProviderExecutionError> {
            Err(ProviderExecutionError::StoreUnavailable)
        }
    }

    impl ProviderTerminalPersistence for Delegate {
        fn commit_terminal(
            &self,
            _: &ProviderTerminalCommitRequest,
        ) -> Result<
            runne_application::provider::ProviderTerminalCommitOutcome,
            ProviderExecutionError,
        > {
            Err(ProviderExecutionError::StoreUnavailable)
        }
    }

    #[test]
    fn only_generation_one_first_ack_fails_and_delegates_afterward() {
        let delegate = Arc::new(Delegate(AtomicUsize::new(0)));
        let first = AckFailureStore::new(Arc::clone(&delegate), 1);
        assert_eq!(
            first.acknowledge_terminal_outbox([1; 16], [2; 32]),
            Err(ProviderExecutionError::StoreUnavailable)
        );
        first.acknowledge_terminal_outbox([1; 16], [2; 32]).unwrap();
        let second = AckFailureStore::new(Arc::clone(&delegate), 2);
        second
            .acknowledge_terminal_outbox([1; 16], [2; 32])
            .unwrap();
        assert_eq!(delegate.0.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod authority_admission_tests;
#[cfg(test)]
mod authority_lease_tests;
#[cfg(test)]
mod authority_test_support;
#[cfg(test)]
mod dispatch_effect_tests;
mod durable_readback;
#[cfg(test)]
mod effect_start_tests;

include!("execution_store/decomposition/part_01.rs");
include!("execution_store/decomposition/part_02.rs");
include!("execution_store/decomposition/part_03.rs");
include!("execution_store/decomposition/part_04.rs");
include!("execution_store/decomposition/part_05.rs");
include!("execution_store/decomposition/part_06.rs");
include!("execution_store/decomposition/part_07.rs");
include!("execution_store/decomposition/part_08.rs");
include!("execution_store/decomposition/part_09.rs");
include!("execution_store/decomposition/part_10.rs");
include!("execution_store/decomposition/part_11.rs");
include!("execution_store/decomposition/part_12.rs");

impl ProviderExecutionStore for SqliteProviderExecutionStore {
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        self.active_journal_key_binding_impl()
    }

    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.activate_journal_key_impl(key)
    }

    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        self.journal_key_reference_count_impl(key)
    }

    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.remove_retired_journal_key_impl(key)
    }

    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.begin_provider_poll_impl(request)
    }

    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        self.append_encrypted_event_impl(request)
    }

    fn load_encrypted_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        self.load_encrypted_events_impl(attempt_id)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        self.load_terminal_pricing_binding_impl(attempt_id)
    }

    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_terminal_outbox_impl()
    }

    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        self.acknowledge_terminal_outbox_impl(outbox_id, receipt_digest)
    }

    fn mark_execution_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        self.mark_execution_uncertain_impl(attempt_id, fencing_token)
    }
}

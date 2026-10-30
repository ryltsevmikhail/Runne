#[cfg(test)]
mod authority_admission_tests;
#[cfg(test)]
mod authority_lease_tests;
#[cfg(test)]
mod authority_renewal_tests;
#[cfg(test)]
mod authority_replay_provider_tests;
#[cfg(test)]
mod authority_row_test_support;
#[cfg(test)]
mod authority_test_support;
#[cfg(test)]
#[path = "execution_store/authority_test_support/canonical_started.rs"]
mod canonical_started_test_support;
#[cfg(test)]
mod dispatch_coordinator_online_expiry_tests;
#[cfg(test)]
mod dispatch_coordinator_online_failure_tests;
#[cfg(test)]
mod dispatch_coordinator_online_tests;
#[cfg(test)]
mod dispatch_effect_tests;
mod durable_readback;
#[cfg(test)]
mod effect_receipt_pause_test_support;
#[cfg(test)]
mod effect_start_tests;
#[cfg(test)]
mod effect_start_v24_tests;
#[cfg(test)]
mod online_claim_provider_tests;
#[cfg(test)]
mod online_effect_deadline_tests;
#[cfg(test)]
mod online_effect_live_boundary_tests;
pub(crate) mod online_effect_proof;
#[cfg(test)]
mod online_effect_start_tests;
mod secondary_profile_grant;
#[cfg(test)]
mod secondary_profile_grant_renewal_tests;
#[cfg(test)]
mod secondary_profile_grant_tests;
use online_effect_proof::{OnlineEffectProofCapabilitySet, OnlineEffectProofState};
#[cfg(test)]
mod online_proof_test_support;
#[cfg(test)]
#[path = "execution_store/remote_identity_resolve_tests.rs"]
mod remote_identity_resolve_tests;
#[cfg(test)]
#[path = "execution_store/remote_identity_tests.rs"]
mod remote_identity_tests;
#[cfg(test)]
#[path = "execution_store/remote_operation_proof_tests.rs"]
mod remote_operation_proof_tests;

include!("execution_store/decomposition/part_01.rs");
include!("execution_store/decomposition/part_02.rs");
include!("execution_store/decomposition/final_send.rs");
include!("execution_store/decomposition/runtime_launch.rs");
include!("execution_store/decomposition/online_effect_start.rs");
include!("execution_store/decomposition/online_effect_proof_install.rs");
include!("execution_store/decomposition/online_issuance.rs");
include!("execution_store/decomposition/part_03.rs");
include!("execution_store/decomposition/poll_revalidation.rs");
include!("execution_store/decomposition/part_04.rs");
include!("execution_store/decomposition/part_05.rs");
include!("execution_store/decomposition/part_05_ack.rs");
include!("execution_store/decomposition/part_06.rs");
include!("execution_store/decomposition/part_06_support.rs");
include!("execution_store/decomposition/part_07.rs");
include!("execution_store/decomposition/part_08.rs");
include!("execution_store/decomposition/part_09.rs");
include!("execution_store/decomposition/part_10.rs");
include!("execution_store/decomposition/part_11.rs");
include!("execution_store/decomposition/part_11_semantic.rs");
#[cfg(feature = "test-support")]
include!("execution_store/decomposition/test_dispatch_attempt_id.rs");
include!("execution_store/decomposition/part_11_security.rs");
include!("execution_store/decomposition/part_12.rs");
include!("execution_store/remote_identity_write.rs");
include!("execution_store/remote_identity_validation.rs");
include!("execution_store/remote_identity_read.rs");
include!("execution_store/remote_identity_scan.rs");
include!("execution_store/remote_identity_scan_find.rs");
include!("execution_store/remote_identity_history.rs");
include!("execution_store/remote_identity_resolve.rs");
include!("execution_store/remote_terminal_write.rs");
include!("execution_store/remote_terminal_source_binding.rs");
include!("execution_store/remote_terminal_settlement_binding.rs");
include!("execution_store/remote_terminal_settlement_write.rs");
include!("execution_store/remote_terminal_publication.rs");
include!("execution_store/remote_terminal_settlement_accounting.rs");
include!("execution_store/remote_terminal_settlement_replay.rs");
include!("execution_store/remote_terminal_audit_receipt.rs");
include!("execution_store/remote_terminal_effects_snapshot.rs");
include!("execution_store/remote_terminal_unknown_snapshot.rs");
include!("execution_store/remote_terminal_unknown_write.rs");
include!("execution_store/remote_terminal_unknown_ack.rs");
include!("execution_store/remote_operation_proof.rs");
include!("execution_store/remote_terminal_read.rs");
include!("execution_store/taskrun_cancel_fence.rs");

pub use secondary_profile_grant::ProviderSecondaryProfileGrant;

impl ProviderExecutionStore for SqliteProviderExecutionStore {
    fn verify_unknown_original_effect(
        &self,
        proof: &runne_application::provider::ProviderUnknownCommittedEffectProof,
    ) -> Result<(), ProviderExecutionError> {
        let state = self
            .online_effect_proof
            .lock()
            .map_err(|_| ProviderExecutionError::JournalKeyUnavailable)?;
        let capability = state
            .as_ref()
            .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
        let fields = online_effect_proof::CommittedEffectProofFields {
            issuance_mac: proof.fields.issuance_mac,
            attempt_id: proof.fields.attempt_id,
            provider_id: proof.fields.provider_id.clone(),
            launch_generation: proof.fields.launch_generation,
            lifecycle_revision: proof.fields.lifecycle_revision,
            credential_fence: proof.fields.credential_fence,
            credential_version: proof.fields.credential_version,
            credential_ref_digest: proof.fields.credential_ref_digest,
            lease_owner: proof.fields.lease_owner,
            lease_expires_at: proof.fields.lease_expires_at,
            lease_fence: proof.fields.lease_fence,
            effect_started_at: proof.fields.effect_started_at,
            effect_expires_at: proof.fields.effect_expires_at,
        };
        if capability.verify_effect(proof.binding, &fields, &proof.mac) {
            Ok(())
        } else {
            Err(ProviderExecutionError::JournalCorrupt)
        }
    }

    fn revalidate_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        self.revalidate_provider_poll_impl(request)
    }

    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        self.active_journal_key_binding_impl()
    }

    fn activate_journal_key(
        &self,
        _key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        Err(ProviderExecutionError::JournalKeyUnavailable)
    }

    fn activate_journal_key_with_keyring(
        &self,
        keyring: &dyn runne_secure_store::ProviderJournalKeyring,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        self.activate_journal_key_impl(keyring, key)
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

    fn pending_terminal_outbox_for_attempt(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_terminal_outbox_for_attempt_impl(attempt_id)
    }

    fn pending_tool_proposal_outbox_for_attempt(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        self.pending_tool_proposal_outbox_for_attempt_impl(attempt_id)
    }

    fn load_remote_attempt_snapshot(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAttemptRecord>,
        ProviderExecutionError,
    > {
        read_remote_attempt_snapshot(self, attempt_id)
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

mod installation_upgrade;
#[cfg(test)]
mod installation_upgrade_tests;

mod terminal_adoption;
#[cfg(test)]
mod terminal_adoption_tests;

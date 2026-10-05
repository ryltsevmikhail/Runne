use super::*;

impl super::DaemonCanonicalProviderService {
    // These values are the authenticated AEAD associated-data tuple for stored tool payloads.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_d2_tool_arguments(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        plaintext: &[u8],
    ) -> Result<runne_store::store::taskrun_tool_invocation::EncryptedToolPayloadV1, ()> {
        let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            self.tail_store.as_ref(),
            self.scanner_store.as_ref(),
            &matcher,
        );
        let profile = self.tool_profile.as_deref().ok_or(())?;
        let execution = RuntimeProviderExecution::new(
            self.keyring.as_ref(),
            self.runtime_store.as_ref(),
            profile,
            self.prohibited_content.as_ref(),
            &redaction,
        );
        execution
            .preflight_existing_active_key(self.runtime_authority_id, self.database_generation)
            .map_err(|_| ())?;
        let (key, payload) = execution
            .seal_taskrun_tool_payload(
                taskrun_id,
                attempt_id,
                cycle_id,
                proposal_index,
                semantic_digest,
                runne_runtime::provider_execution::TaskRunToolPayloadRole::Arguments,
                plaintext,
            )
            .map_err(|_| ())?;
        Ok(runne_store::store::taskrun_tool_invocation::EncryptedToolPayloadV1 { key, payload })
    }

    pub(crate) fn seal_d2_tool_receipt(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        plaintext: &[u8],
    ) -> Result<runne_store::store::taskrun_tool_invocation::EncryptedToolPayloadV1, ()> {
        let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            self.tail_store.as_ref(),
            self.scanner_store.as_ref(),
            &matcher,
        );
        let profile = self.tool_profile.as_deref().ok_or(())?;
        let execution = RuntimeProviderExecution::new(
            self.keyring.as_ref(),
            self.runtime_store.as_ref(),
            profile,
            self.prohibited_content.as_ref(),
            &redaction,
        );
        execution
            .preflight_existing_active_key(self.runtime_authority_id, self.database_generation)
            .map_err(|_| ())?;
        let (key, payload) = execution
            .seal_taskrun_tool_payload(
                taskrun_id,
                attempt_id,
                cycle_id,
                proposal_index,
                semantic_digest,
                runne_runtime::provider_execution::TaskRunToolPayloadRole::Receipt,
                plaintext,
            )
            .map_err(|_| ())?;
        Ok(runne_store::store::taskrun_tool_invocation::EncryptedToolPayloadV1 { key, payload })
    }

    // These values are the authenticated AEAD associated-data tuple for stored tool payloads.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_d2_tool_receipt(
        &self,
        key: runne_application::provider::ProviderJournalKeyBinding,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        payload: &runne_application::provider::ProviderEncryptedPayload,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
        self.open_d2_tool_payload(
            key,
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index,
            semantic_digest,
            runne_runtime::provider_execution::TaskRunToolPayloadRole::Receipt,
            payload,
        )
    }

    // Arguments and receipts use the same exact authenticated identity tuple.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_d2_tool_arguments(
        &self,
        key: runne_application::provider::ProviderJournalKeyBinding,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        payload: &runne_application::provider::ProviderEncryptedPayload,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
        self.open_d2_tool_payload(
            key,
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index,
            semantic_digest,
            runne_runtime::provider_execution::TaskRunToolPayloadRole::Arguments,
            payload,
        )
    }

    // Role and payload complete the cryptographic context; callers cannot supply raw plaintext.
    #[allow(clippy::too_many_arguments)]
    fn open_d2_tool_payload(
        &self,
        key: runne_application::provider::ProviderJournalKeyBinding,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        role: runne_runtime::provider_execution::TaskRunToolPayloadRole,
        payload: &runne_application::provider::ProviderEncryptedPayload,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ()> {
        let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            self.tail_store.as_ref(),
            self.scanner_store.as_ref(),
            &matcher,
        );
        let profile = self.tool_profile.as_deref().ok_or(())?;
        let execution = RuntimeProviderExecution::new(
            self.keyring.as_ref(),
            self.runtime_store.as_ref(),
            profile,
            self.prohibited_content.as_ref(),
            &redaction,
        );
        execution
            .open_taskrun_tool_payload(
                key,
                taskrun_id,
                attempt_id,
                cycle_id,
                proposal_index,
                semantic_digest,
                role,
                payload,
            )
            .map_err(|_| ())
    }
}

/// Purpose bound into the authenticated tool payload envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunToolPayloadRole {
    Arguments,
    Receipt,
}

impl TaskRunToolPayloadRole {
    const fn code(self) -> u8 {
        match self {
            Self::Arguments => 1,
            Self::Receipt => 2,
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::Arguments => 8192,
            Self::Receipt => 16384,
        }
    }
}

const TASKRUN_TOOL_AAD_V1: &[u8] = b"GOCODE_TASKRUN_TOOL_PAYLOAD_AAD_V1\0";

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Encrypts exact bounded tool data using the active provider journal key.
    /// The returned payload must be persisted atomically with nonce registration.
    pub fn seal_taskrun_tool_payload(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        role: TaskRunToolPayloadRole,
        plaintext: &[u8],
    ) -> Result<(ProviderJournalKeyBinding, ProviderEncryptedPayload), RuntimeProviderExecutionError>
    {
        if plaintext.is_empty() || plaintext.len() > role.maximum_bytes() {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let key = self.current_key()?;
        let material = self.load_key(key)?;
        let aad = taskrun_tool_payload_aad(
            key,
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index,
            semantic_digest,
            role,
        );
        let payload = self.seal(&material, &aad, plaintext)?;
        Ok((key, payload))
    }

    /// Opens an authenticated payload only under its original journal key and binding.
    pub fn open_taskrun_tool_payload(
        &self,
        key: ProviderJournalKeyBinding,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        proposal_index: u32,
        semantic_digest: runne_domain::id::IntegrityDigest,
        role: TaskRunToolPayloadRole,
        payload: &ProviderEncryptedPayload,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, RuntimeProviderExecutionError> {
        if payload.plaintext_len() == 0 || payload.plaintext_len() > role.maximum_bytes() as u64 {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let material = self.load_key(key)?;
        let aad = taskrun_tool_payload_aad(
            key,
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index,
            semantic_digest,
            role,
        );
        open_payload(&material, &aad, payload).map(zeroize::Zeroizing::new)
    }
}

fn taskrun_tool_payload_aad(
    key: ProviderJournalKeyBinding,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    cycle_id: runne_domain::id::CycleId,
    proposal_index: u32,
    semantic_digest: runne_domain::id::IntegrityDigest,
    role: TaskRunToolPayloadRole,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(192);
    aad.extend_from_slice(TASKRUN_TOOL_AAD_V1);
    aad.push(role.code());
    aad.extend_from_slice(taskrun_id.as_bytes());
    aad.extend_from_slice(attempt_id.as_bytes());
    aad.extend_from_slice(cycle_id.as_bytes());
    aad.extend_from_slice(&proposal_index.to_be_bytes());
    aad.extend_from_slice(semantic_digest.as_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
    aad.extend_from_slice(&key.runtime_authority_id());
    aad.extend_from_slice(&key.database_generation().to_be_bytes());
    aad
}

use super::{
    BundledRuntimeLifecycleState, ProtectedActivationKeys, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeSupervisor, ProtectedChannel,
    read_frame, write_frame,
};
use runne_api::{ProtectedCredentialRecoveryBootstrap, ProtectedCredentialRecoveryCodec};
mod interleaved;

/// Native-only, single-use observation of an accepted cleanup attempt.
pub struct PreparedProtectedCredentialRecovery {
    codec: ProtectedCredentialRecoveryCodec,
    bootstrap: ProtectedCredentialRecoveryBootstrap,
}

impl PreparedProtectedCredentialRecovery {
    fn begin(
        channel: &mut ProtectedChannel,
        keys: &ProtectedActivationKeys,
        bootstrap: ProtectedCredentialRecoveryBootstrap,
        operation: [u8; 16],
    ) -> Result<Self, ProtectedBundledRuntimeError> {
        let mut codec = ProtectedCredentialRecoveryCodec::for_desktop(keys, bootstrap.clone())
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let request = codec
            .encode_desktop_request(operation)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        write_frame(channel, &request)?;
        let frame = read_frame(channel)?;
        let offer = codec
            .decode_daemon_offer(&frame, now_seconds()?)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let accept = codec
            .encode_desktop_accept(&offer, now_seconds()?)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
        write_frame(channel, &accept)?;
        Ok(Self { codec, bootstrap })
    }

    fn finish(
        mut self,
        channel: &mut ProtectedChannel,
        current: &ProtectedCredentialRecoveryBootstrap,
    ) -> Result<runne_api::ProviderCredentialOperationSnapshotV2, ProtectedBundledRuntimeError>
    {
        if &self.bootstrap != current {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        self.codec
            .decode_daemon_terminal(&read_frame(channel)?)
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}

impl ProtectedBundledRuntimeSupervisor {
    /// Accepts one existing Prepared cleanup; never creates a native Begin or prompts for a secret.
    ///
    /// # Errors
    /// Fails closed outside the current Ready V3 session or on rejected recovery evidence.
    pub fn begin_protected_credential_recovery(
        &mut self,
        operation: [u8; 16],
    ) -> Result<PreparedProtectedCredentialRecovery, ProtectedBundledRuntimeError> {
        let process = self.recovery_process()?;
        let bootstrap = process.recovery_bootstrap()?;
        PreparedProtectedCredentialRecovery::begin(
            &mut process.channel,
            &process.keys,
            bootstrap,
            operation,
        )
    }

    /// Reads terminal evidence after the native `ControlOnly` writer handoff.
    ///
    /// # Errors
    /// Rejects rotated sessions and malformed, replayed or unrelated terminal evidence.
    pub fn finish_protected_credential_recovery(
        &mut self,
        recovery: PreparedProtectedCredentialRecovery,
    ) -> Result<runne_api::ProviderCredentialOperationSnapshotV2, ProtectedBundledRuntimeError>
    {
        let process = self.recovery_process()?;
        let current = process.recovery_bootstrap()?;
        let snapshot = recovery.finish(&mut process.channel, &current)?;
        process.record_enrollment_terminal()?;
        Ok(snapshot)
    }

    fn recovery_process(
        &mut self,
    ) -> Result<&mut ProtectedBundledRuntimeProcess, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}

impl ProtectedBundledRuntimeProcess {
    pub(super) fn recovery_bootstrap(
        &self,
    ) -> Result<ProtectedCredentialRecoveryBootstrap, ProtectedBundledRuntimeError> {
        let (owned, facts) = self.v3_enrollment_facts()?;
        ProtectedCredentialRecoveryBootstrap::from_owned_launch(
            &owned,
            facts.binding(),
            facts.publication_public_key(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
    }
}

fn now_seconds() -> Result<u64, ProtectedBundledRuntimeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)
}

#[cfg(test)]
mod tests;

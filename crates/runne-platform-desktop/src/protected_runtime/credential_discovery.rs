use super::{
    BundledRuntimeLifecycleState, ProtectedActivationKeys, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, ProtectedChannel, ProtectedProcessActivation, random_nonce,
    read_frame, write_frame,
};
mod interleaved;
#[cfg(feature = "test-support")]
pub(super) use interleaved::{prepare, reap};
#[cfg(feature = "test-support")]
pub use interleaved::{
    test_only_crossed_discovery, test_only_crossed_renewal, test_only_crossed_round,
};

fn exchange(
    channel: &mut ProtectedChannel,
    keys: &ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
    exchange_codec(
        channel,
        runne_api::ProtectedCredentialDiscoveryCodec::new(keys, owned),
    )
}

fn exchange_codec(
    channel: &mut ProtectedChannel,
    mut codec: runne_api::ProtectedCredentialDiscoveryCodec,
) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
    let nonce = random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let request = codec
        .encode_request(nonce)
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    write_frame(channel, &request)?;
    codec
        .decode_response(&read_frame(channel)?)
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
}

impl ProtectedBundledRuntimeSupervisor {
    /// Reads startup metadata while remaining in V2. The native caller retains
    /// the operation/updater leases and separately authorizes any V3 transition.
    /// Returns `None` when V3 is already active; startup must not replay its transition.
    ///
    /// # Errors
    /// Rejects non-Ready/non-V2 state and fences ambiguous channel exchanges.
    pub fn discover_startup_credential_cleanup(
        &mut self,
    ) -> Result<Option<Vec<[u8; 16]>>, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if matches!(process.activation, ProtectedProcessActivation::V3 { .. }) {
            return Ok(None);
        }
        let ProtectedProcessActivation::V2 { owned, .. } = &process.activation else {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        };
        if process.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let codec = runne_api::ProtectedCredentialDiscoveryCodec::for_startup(&process.keys, owned);
        let result = exchange_codec(&mut process.channel, codec);
        if result.is_err() {
            process.fence_ambiguous_transition();
        }
        result.map(Some)
    }

    /// Reads pending cleanup IDs after terminal observation, before renewal.
    /// Native caller must retain runtime/updater leases. IDs grant no authority.
    ///
    /// # Errors
    /// Rejects nonterminal or renewed sessions and fences ambiguous channel I/O.
    pub fn discover_prepared_credential_cleanup(
        &mut self,
    ) -> Result<Vec<[u8; 16]>, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let (owned, facts) = process.v3_enrollment_facts()?;
        if process.graceful_requested || facts.terminal_session != Some(*owned.session_id()) {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let result = exchange(&mut process.channel, &process.keys, &owned);
        if result.is_err() {
            process.fence_ambiguous_transition();
        }
        result
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests;

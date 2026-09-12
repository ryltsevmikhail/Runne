//! Read-only native admission before the first enrollment status request.

use super::*;
use runne_api::{ProtectedCredentialStatusAckV2, ProtectedCredentialStatusRequestV2};

#[cfg(test)]
mod tests;

impl ProtectedBundledRuntimeSupervisor {
    /// Authenticates measured status claims without changing runtime sessions.
    ///
    /// # Errors
    /// Fails closed on stale ownership, native measurements or control replies.
    pub fn prepare_credential_status(
        &mut self,
        confirmed: &crate::ConfirmedInstalledNativeEnrollment,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let facts = confirmed
            .enrollment_transition_facts()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let generation = std::num::NonZeroU64::new(facts.supervisor_generation)
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claims = EnrollmentTransitionClaims::new(
            facts.release_tuple_digest,
            facts.qualification_binding_digest,
            confirmed.current_desktop_peer_binding_digest(generation)?,
            facts.supervisor_generation,
        );
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .prepare_credential_status(&claims, confirmed.installed_generation())
    }
}

impl ProtectedBundledRuntimeProcess {
    fn prepare_credential_status(
        &mut self,
        claims: &EnrollmentTransitionClaims,
        installed_generation: u64,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.graceful_requested || self.status()? != BundledRuntimeProcessStatus::Running {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let owned = match &self.activation {
            ProtectedProcessActivation::V2 { owned, .. } => owned.clone(),
            // V3's authenticated native transcript already published exact facts.
            ProtectedProcessActivation::V3 { owned, .. } => {
                let binding = owned.enrollment_binding();
                return if *binding.release_tuple_digest() == claims.release_tuple_digest
                    && *binding.qualification_binding_digest()
                        == claims.qualification_binding_digest
                    && *binding.desktop_peer_binding_digest() == claims.desktop_peer_binding_digest
                    && binding.desktop_supervisor_generation()
                        == claims.desktop_supervisor_generation
                {
                    Ok(())
                } else {
                    Err(ProtectedBundledRuntimeError::OwnershipMismatch)
                };
            }
            _ => return Err(ProtectedBundledRuntimeError::InvalidState),
        };
        let sequence = self
            .root_control_sequence
            .checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
            owned.clone(),
            sequence,
            random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?,
            claims.release_tuple_digest,
            claims.qualification_binding_digest,
            claims.desktop_peer_binding_digest,
            claims.desktop_supervisor_generation,
        )
        .map_err(launch_error)?;
        prepare.sign(&self.keys);
        let request =
            ProtectedCredentialStatusRequestV2::new(prepare, &self.keys).map_err(launch_error)?;
        let frame = request
            .encode_frame()
            .map_err(|_| launch_error(LaunchAuthorityError::InvalidContract))?;
        // A partial write or unexpected reply makes this stream unusable.
        self.root_control_sequence = sequence;
        let result = (|| {
            write_frame(&mut self.channel, &Zeroizing::new(frame))?;
            let reply = Zeroizing::new(read_frame(&mut self.channel)?);
            let ack = ProtectedCredentialStatusAckV2::decode_frame(&reply)
                .map_err(|_| launch_error(LaunchAuthorityError::InvalidContract))?;
            let verified = ack
                .verify_exact_view(&request, &self.keys)
                .map_err(launch_error)?;
            if verified.installed_generation() != installed_generation {
                return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
            }
            Ok(())
        })();
        if result.is_err() {
            self.fence_ambiguous_transition();
        }
        result
    }
}

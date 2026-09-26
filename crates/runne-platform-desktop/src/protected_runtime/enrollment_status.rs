//! Read-only native admission before the first enrollment status request.

use super::{
    BundledRuntimeLifecycleState, BundledRuntimeProcessStatus, EnrollmentTransitionClaims,
    LaunchAuthorityError, ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedProcessActivation, Zeroizing, launch_error, random_nonce, read_frame, write_frame,
};
#[cfg(all(test, target_os = "macos"))]
use super::{
    Duration, ProtectedOwnedLaunchV2, UnixStream, v2_launch_fixture, v2_launch_fixture_with_secret,
    v2_process,
};
use runne_api::{ProtectedCredentialStatusAckV2, ProtectedCredentialStatusRequestV2};

#[cfg(all(test, target_os = "linux"))]
#[path = "enrollment_status/linux_tests.rs"]
mod linux_tests;
#[cfg(all(test, target_os = "macos"))]
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
        #[cfg(target_os = "linux")]
        let peer_generation = self
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .credential_status_peer_generation(facts.supervisor_generation)?;
        #[cfg(not(target_os = "linux"))]
        let peer_generation = facts.supervisor_generation;
        let generation = std::num::NonZeroU64::new(peer_generation)
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let claims = EnrollmentTransitionClaims::new(
            facts.release_tuple_digest,
            facts.qualification_binding_digest,
            confirmed.current_desktop_peer_binding_digest(generation)?,
            peer_generation,
        );
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .prepare_credential_status(&claims, confirmed.installed_generation())
    }
}

impl ProtectedBundledRuntimeProcess {
    #[cfg(target_os = "linux")]
    const fn credential_status_peer_generation(
        &self,
        confirmed_generation: u64,
    ) -> Result<u64, ProtectedBundledRuntimeError> {
        match &self.activation {
            ProtectedProcessActivation::V2 { .. } => Ok(confirmed_generation),
            ProtectedProcessActivation::V3 { owned, .. }
                if owned.launch_generation() == confirmed_generation =>
            {
                Ok(owned.enrollment_binding().desktop_supervisor_generation())
            }
            _ => Err(ProtectedBundledRuntimeError::OwnershipMismatch),
        }
    }

    pub(super) fn prepare_credential_status(
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
            owned,
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

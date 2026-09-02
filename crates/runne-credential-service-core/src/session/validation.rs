use runne_api::CredentialServiceRegistrationBinding;
use runne_provider::{
    CredentialRuntimeReadBinding, CredentialServiceDeadline, CredentialServiceDisposition,
    CredentialServiceEpoch, CredentialServiceIngressRequest, CredentialServiceProtocolCodec,
};

use super::{
    CredentialRegistrationOutcome, CredentialServiceCore, CredentialServiceIngressFailure,
};

impl CredentialServiceCore {
    pub(super) fn classify_registration(
        &self,
        candidate: &CredentialServiceRegistrationBinding,
        now: u64,
    ) -> Result<CredentialRegistrationOutcome, ()> {
        if candidate.service_epoch() != &self.epoch.as_bytes()
            || candidate.expires_at_unix_millis() <= now
        {
            return Err(());
        }
        let Some(current) = self.sessions.get(candidate.installation_owner()) else {
            return Ok(CredentialRegistrationOutcome::Installed);
        };
        if candidate == &current.binding {
            return Ok(CredentialRegistrationOutcome::Idempotent);
        }
        let old = &current.binding;
        let release_is_current = candidate.installed_generation() > old.installed_generation()
            || candidate.release_binding() == old.release_binding();
        if candidate.join_attempt() > old.join_attempt()
            && candidate.daemon_authority_generation() >= old.daemon_authority_generation()
            && candidate.runtime_generation() > old.runtime_generation()
            && candidate.supervisor_generation() >= old.supervisor_generation()
            && candidate.installed_generation() >= old.installed_generation()
            && candidate.protected_session_id() != old.protected_session_id()
            && candidate.challenge_nonce() != old.challenge_nonce()
            && release_is_current
        {
            Ok(CredentialRegistrationOutcome::Superseded)
        } else {
            Err(())
        }
    }

    pub(super) fn require_live_session(
        &mut self,
        owner: [u8; 32],
        now: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        let live = self
            .sessions
            .get(&owner)
            .is_some_and(|session| session.binding.expires_at_unix_millis() > now);
        if live {
            return Ok(());
        }
        self.sessions.remove(&owner);
        self.admissions.clear_owner(owner);
        Err(CredentialServiceDisposition::SessionMissing {
            current_epoch: self.epoch,
        })
    }

    pub(super) fn decode_runtime(
        &mut self,
        bytes: &[u8],
        now: u64,
    ) -> Result<([u8; 32], CredentialServiceIngressRequest), CredentialServiceIngressFailure> {
        let owner = runne_api::CredentialServiceSessionAuthenticator::runtime_routing_owner(bytes)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        self.require_live_session(owner, now)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let session = self
            .sessions
            .get(&owner)
            .ok_or(CredentialServiceIngressFailure::Invalidate)?;
        let verified = session
            .authenticator
            .verify_runtime_request(owner, bytes)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let mut decoded = Err(CredentialServiceIngressFailure::Invalidate);
        verified.consume(|payload| {
            decoded = CredentialServiceProtocolCodec::decode_runtime_request(payload)
                .map(|request| (owner, request))
                .map_err(|_| CredentialServiceIngressFailure::Invalidate);
        });
        decoded
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn validate_runtime_binding(
        &mut self,
        owner: [u8; 32],
        inner_owner: [u8; 32],
        epoch: CredentialServiceEpoch,
        session_id: [u8; 16],
        runtime_generation: u64,
        release_binding: [u8; 32],
        sequence: u64,
        deadline: CredentialServiceDeadline,
        now: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        self.require_live_session(owner, now)?;
        let session = self
            .sessions
            .get(&owner)
            .ok_or(CredentialServiceDisposition::Denied)?;
        if inner_owner != owner
            || epoch != self.epoch
            || session_id != *session.binding.protected_session_id()
            || runtime_generation != session.binding.runtime_generation()
            || release_binding != *session.binding.release_binding()
            || sequence <= session.last_sequence
            || now < deadline.issued_at_unix_millis()
            || now >= deadline.expires_at_unix_millis()
            || deadline.expires_at_unix_millis() > session.binding.expires_at_unix_millis()
        {
            return Err(CredentialServiceDisposition::Denied);
        }
        Ok(())
    }

    pub(super) fn validate_read(
        &mut self,
        owner: [u8; 32],
        binding: &CredentialRuntimeReadBinding,
        now: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        self.validate_runtime_binding(
            owner,
            binding.installation_owner(),
            binding.epoch(),
            binding.session(),
            binding.runtime_generation(),
            binding.release_binding().as_bytes(),
            binding.sequence().get(),
            binding.deadline(),
            now,
        )
    }

    pub(super) fn advance_sequence(
        &mut self,
        owner: [u8; 32],
        sequence: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        let session = self
            .sessions
            .get_mut(&owner)
            .ok_or(CredentialServiceDisposition::Denied)?;
        session.last_sequence = sequence;
        Ok(())
    }
}

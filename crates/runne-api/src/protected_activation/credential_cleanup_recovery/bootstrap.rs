use super::*;

/// Desktop-known launch facts; daemon/database facts arrive in the signed offer.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedCredentialRecoveryBootstrap {
    installation: [u8; 32],
    release: [u8; 32],
    session: [u8; 32],
    peer: [u8; 32],
    broker: [u8; 32],
    supervisor: u64,
}

impl ProtectedCredentialRecoveryBootstrap {
    /// Uses the authenticated launch and retained daemon-owned rendezvous facts.
    /// This metadata is not credential authority or live-host admission.
    pub fn from_owned_launch(
        owned: &crate::ProtectedCredentialEnrollmentOwnedLaunchV3,
        channel: [u8; 32],
        publication_key: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        if channel == [0; 32] || publication_key == [0; 32] {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut hash = Sha256::new();
        hash.update(b"gocode/provider-credential-enrollment/session/v1\0");
        for part in [
            owned.launch_authority_id().as_slice(),
            owned.session_id().as_slice(),
            owned.daemon_instance_id().as_slice(),
            &owned.launch_generation().to_be_bytes(),
        ] {
            hash.update((part.len() as u32).to_be_bytes());
            hash.update(part);
        }
        let binding = owned.enrollment_binding();
        let release = *binding.release_tuple_digest();
        Self::new(
            *binding.installation_identity_digest(),
            release,
            hash.finalize().into(),
            *binding.desktop_peer_binding_digest(),
            crate::protected_credential_broker_evidence_binding(release, channel, publication_key),
            binding.desktop_supervisor_generation(),
        )
    }

    /// Validates representation; callers remain responsible for authenticating facts.
    pub fn new(
        installation: [u8; 32],
        release: [u8; 32],
        session: [u8; 32],
        peer: [u8; 32],
        broker: [u8; 32],
        supervisor: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if [installation, release, session, peer, broker].contains(&[0; 32])
            || supervisor == 0
            || supervisor > i64::MAX as u64
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            installation,
            release,
            session,
            peer,
            broker,
            supervisor,
        })
    }

    pub(super) fn from_context(c: &ProtectedCredentialRecoveryContext) -> Self {
        Self {
            installation: c.installation,
            release: c.release,
            session: c.session,
            peer: c.peer,
            broker: c.broker,
            supervisor: c.supervisor,
        }
    }

    pub(super) fn require_context(
        &self,
        c: &ProtectedCredentialRecoveryContext,
    ) -> Result<(), LaunchAuthorityError> {
        if self != &Self::from_context(c) {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(())
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"runne/credential-cleanup-recovery/request-launch/v1\0");
        for value in [
            self.installation,
            self.release,
            self.session,
            self.peer,
            self.broker,
        ] {
            hash.update(value);
        }
        hash.update(self.supervisor.to_be_bytes());
        hash.finalize().into()
    }
}

use std::time::{Duration, Instant};

use runne_api::CredentialServiceRegistrationBinding;
use runne_provider::{CredentialServiceEpoch, ServiceQualificationCommon};

use super::clocks::LockedCredentialServiceClocks;

/// Copyable private binding facts; no raw qualification frame is retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct QualificationBinding {
    pub(super) service_epoch: [u8; 16],
    pub(super) protected_session_id: [u8; 16],
    pub(super) daemon_authority_generation: u64,
    pub(super) runtime_generation: u64,
    pub(super) supervisor_generation: u64,
    pub(super) installed_generation: u64,
    pub(super) installation_owner: [u8; 32],
    pub(super) release_binding: [u8; 32],
    pub(super) challenge_nonce: [u8; 16],
    pub(super) join_attempt: u64,
    pub(super) registration_expires_at_unix_millis: u64,
    pub(super) sequence: u64,
    pub(super) transfer_id: [u8; 16],
    pub(super) operation_id: [u8; 16],
    pub(super) provider_ticket_attempt: u64,
    pub(super) provider_ticket_binding_digest: [u8; 32],
    pub(super) qualification_fault_ticket_sha256: [u8; 32],
    pub(super) release_frame_sha256: [u8; 32],
    pub(super) admission_bundle_sha256: [u8; 32],
    pub(super) issued_at_unix_millis: u64,
    pub(super) expires_at_unix_millis: u64,
}

impl QualificationBinding {
    pub(super) const fn zero_for_test() -> Self {
        Self {
            service_epoch: [0; 16],
            protected_session_id: [0; 16],
            daemon_authority_generation: 0,
            runtime_generation: 0,
            supervisor_generation: 0,
            installed_generation: 0,
            installation_owner: [0; 32],
            release_binding: [0; 32],
            challenge_nonce: [0; 16],
            join_attempt: 0,
            registration_expires_at_unix_millis: 0,
            sequence: 0,
            transfer_id: [0; 16],
            operation_id: [0; 16],
            provider_ticket_attempt: 0,
            provider_ticket_binding_digest: [0; 32],
            qualification_fault_ticket_sha256: [0; 32],
            release_frame_sha256: [0; 32],
            admission_bundle_sha256: [0; 32],
            issued_at_unix_millis: 0,
            expires_at_unix_millis: 0,
        }
    }

    pub(super) const fn from_common(common: &ServiceQualificationCommon) -> Self {
        Self {
            service_epoch: common.service_epoch,
            protected_session_id: common.protected_session_id,
            daemon_authority_generation: common.daemon_authority_generation,
            runtime_generation: common.runtime_generation,
            supervisor_generation: common.supervisor_generation,
            installed_generation: common.installed_generation,
            installation_owner: common.installation_owner,
            release_binding: common.release_binding,
            challenge_nonce: common.challenge_nonce,
            join_attempt: common.join_attempt,
            registration_expires_at_unix_millis: common.registration_expires_at_unix_millis,
            sequence: common.sequence,
            transfer_id: common.transfer_id,
            operation_id: common.operation_id,
            provider_ticket_attempt: common.provider_ticket_attempt,
            provider_ticket_binding_digest: common.provider_ticket_binding_digest,
            qualification_fault_ticket_sha256: common.qualification_fault_ticket_sha256,
            release_frame_sha256: common.release_frame_sha256,
            admission_bundle_sha256: common.admission_bundle_sha256,
            issued_at_unix_millis: common.issued_at_unix_millis,
            expires_at_unix_millis: common.expires_at_unix_millis,
        }
    }

    pub(super) fn matches_registration(
        &self,
        epoch: &CredentialServiceEpoch,
        registration: &CredentialServiceRegistrationBinding,
    ) -> bool {
        self.service_epoch == epoch.as_bytes()
            && self.protected_session_id == *registration.protected_session_id()
            && self.daemon_authority_generation == registration.daemon_authority_generation()
            && self.runtime_generation == registration.runtime_generation()
            && self.supervisor_generation == registration.supervisor_generation()
            && self.installed_generation == registration.installed_generation()
            && self.installation_owner == *registration.installation_owner()
            && self.release_binding == *registration.release_binding()
            && self.challenge_nonce == *registration.challenge_nonce()
            && self.join_attempt == registration.join_attempt()
            && self.registration_expires_at_unix_millis == registration.expires_at_unix_millis()
    }

    pub(super) fn fresh_deadline(
        &self,
        clocks: &LockedCredentialServiceClocks,
    ) -> Result<Instant, ()> {
        let wall_now = clocks.wall_unix_millis();
        if self.issued_at_unix_millis > wall_now
            || wall_now >= self.expires_at_unix_millis
            || self.expires_at_unix_millis > self.registration_expires_at_unix_millis
        {
            return Err(());
        }
        let remaining = self
            .expires_at_unix_millis
            .checked_sub(wall_now)
            .ok_or(())?;
        let ttl = remaining.min(5_000);
        if ttl == 0 {
            return Err(());
        }
        clocks
            .monotonic_now()
            .checked_add(Duration::from_millis(ttl))
            .ok_or(())
    }

    pub(super) fn same_transfer(&self, other: &Self) -> bool {
        let mut left = *self;
        let mut right = *other;
        left.sequence = 0;
        right.sequence = 0;
        left == right
    }
}

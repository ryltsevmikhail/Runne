use core::fmt;
use std::time::{Duration, Instant};

use super::ProviderEffectStartReceipt;
use runne_application::provider::ProviderJournalKeyBinding;

pub(super) struct OnlineEffectReadback {
    pub(super) attempt_id: [u8; 16],
    pub(super) provider: String,
    pub(super) launch_generation: u64,
    pub(super) lifecycle_revision: u64,
    pub(super) credential_fence: u64,
    pub(super) credential_version: u64,
    pub(super) ref_digest: [u8; 32],
    pub(super) effect_started_at: i64,
    pub(super) effect_expires_at: i64,
    pub(super) permit_id: [u8; 16],
    pub(super) idempotency_key: String,
    pub(super) prepared_digest: [u8; 32],
    pub(super) render_digest: [u8; 32],
    pub(super) profile_digest: [u8; 32],
    pub(super) dispatch_fence: u64,
    pub(super) token_reservation_id: [u8; 16],
    pub(super) cost_reservation_id: [u8; 16],
    pub(super) lease_owner: [u8; 16],
    pub(super) lease_expires_at: i64,
    pub(super) lease_fence: u64,
    pub(super) effect_mac: [u8; 32],
    pub(super) proof_binding: ProviderJournalKeyBinding,
    pub(super) issuance_mac: [u8; 32],
}

/// Online-only receipt reconstructed from a committed effect/binding row.
/// It cannot be cloned or deserialized into a second transport authorization.
pub(crate) struct ProviderOnlineEffectStartReceipt {
    attempt_id: [u8; 16],
    provider: String,
    launch_generation: u64,
    lifecycle_revision: u64,
    credential_fence: u64,
    credential_version: u64,
    ref_digest: [u8; 32],
    effect: ProviderEffectStartReceipt,
}

impl fmt::Debug for ProviderOnlineEffectStartReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOnlineEffectStartReceipt")
            .field("binding", &"<durable-online-effect>")
            .finish()
    }
}

impl ProviderOnlineEffectStartReceipt {
    pub(crate) fn install_final_send_authority(
        &mut self,
        authority: crate::provider::ProviderFinalSendAuthority,
    ) {
        self.effect.install_final_send_authority(authority);
    }

    pub(super) fn from_readback(readback: OnlineEffectReadback, deadline_seconds: u64) -> Self {
        let provider = readback.provider;
        Self {
            attempt_id: readback.attempt_id,
            provider: provider.clone(),
            launch_generation: readback.launch_generation,
            lifecycle_revision: readback.lifecycle_revision,
            credential_fence: readback.credential_fence,
            credential_version: readback.credential_version,
            ref_digest: readback.ref_digest,
            effect: ProviderEffectStartReceipt {
                expires_at: readback.effect_expires_at,
                attempt_id: readback.attempt_id,
                permit_id: readback.permit_id,
                provider_idempotency_key: readback.idempotency_key,
                prepared_digest: readback.prepared_digest,
                render_digest: readback.render_digest,
                profile_digest: readback.profile_digest,
                fencing_token: readback.dispatch_fence,
                token_reservation_id: readback.token_reservation_id,
                cost_reservation_id: readback.cost_reservation_id,
                deadline: Instant::now() + Duration::from_secs(deadline_seconds),
                credential_provider: provider,
                credential_version: readback.credential_version,
                credential_ref_digest: readback.ref_digest,
                credential_owner: readback.lease_owner,
                credential_expires_at: readback.lease_expires_at,
                credential_fencing_token: readback.lease_fence,
                final_send: None,
            },
        }
    }

    #[cfg(test)]
    pub(crate) const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    #[cfg(test)]
    pub(crate) const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    #[cfg(test)]
    pub(crate) const fn credential_fence(&self) -> u64 {
        self.credential_fence
    }

    #[cfg(test)]
    pub(crate) const fn credential_version(&self) -> u64 {
        self.credential_version
    }

    #[cfg(test)]
    pub(crate) const fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt_id
    }

    #[cfg(test)]
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    #[cfg(test)]
    pub(crate) const fn ref_digest(&self) -> &[u8; 32] {
        &self.ref_digest
    }

    /// Converts the same committed V26 readback into the legacy adapter token.
    pub(crate) fn into_effect_receipt(self) -> ProviderEffectStartReceipt {
        let Self {
            attempt_id,
            provider,
            launch_generation,
            lifecycle_revision,
            credential_fence,
            credential_version,
            ref_digest,
            effect,
        } = self;
        let _durable_online_tuple = (
            attempt_id,
            provider,
            launch_generation,
            lifecycle_revision,
            credential_fence,
            credential_version,
            ref_digest,
        );
        effect
    }
}

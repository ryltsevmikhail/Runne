use runne_application::provider::ProviderJournalKeyBinding;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuanceProofFields {
    pub(crate) proof_version: u64,
    pub(crate) key: ProviderJournalKeyBinding,
    pub(crate) runtime_authority_id: [u8; 16],
    pub(crate) database_generation: u64,
    pub(crate) provider_id: String,
    pub(crate) provider_idempotency_key: String,
    pub(crate) call_id: [u8; 16],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) authority_id: [u8; 16],
    pub(crate) authority_revision: u64,
    pub(crate) semantic_digest: [u8; 32],
    pub(crate) permit_id: [u8; 16],
    pub(crate) token_reservation_id: [u8; 16],
    pub(crate) cost_reservation_id: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) fencing_token: u64,
    pub(crate) prepared_digest: [u8; 32],
    pub(crate) render_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) pricing_revision_digest: [u8; 32],
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
}

impl IssuanceProofFields {
    pub(super) fn encode(&self) -> Vec<u8> {
        let proof_version = self.proof_version.to_be_bytes();
        let key_id = self.key.key_id();
        let key_version = self.key.key_version().to_be_bytes();
        let key_authority = self.key.runtime_authority_id();
        let key_generation = self.key.database_generation().to_be_bytes();
        let database_generation = self.database_generation.to_be_bytes();
        let authority_revision = self.authority_revision.to_be_bytes();
        let generation = self.generation.to_be_bytes();
        let fencing_token = self.fencing_token.to_be_bytes();
        let issued_at = self.issued_at.to_be_bytes();
        let expires_at = self.expires_at.to_be_bytes();
        frame(&[
            &proof_version,
            &key_id,
            &key_version,
            &key_authority,
            &key_generation,
            &self.runtime_authority_id,
            &database_generation,
            self.provider_id.as_bytes(),
            self.provider_idempotency_key.as_bytes(),
            &self.call_id,
            &self.attempt_id,
            &self.authority_id,
            &authority_revision,
            &self.semantic_digest,
            &self.permit_id,
            &self.token_reservation_id,
            &self.cost_reservation_id,
            &generation,
            &fencing_token,
            &self.prepared_digest,
            &self.render_digest,
            &self.profile_digest,
            &self.pricing_revision_digest,
            &issued_at,
            &expires_at,
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedEffectProofFields {
    pub(crate) issuance_mac: [u8; 32],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) provider_id: String,
    pub(crate) launch_generation: u64,
    pub(crate) lifecycle_revision: u64,
    pub(crate) credential_fence: u64,
    pub(crate) credential_version: u64,
    pub(crate) credential_ref_digest: [u8; 32],
    pub(crate) lease_owner: [u8; 16],
    pub(crate) lease_expires_at: i64,
    pub(crate) lease_fence: u64,
    pub(crate) effect_started_at: i64,
    pub(crate) effect_expires_at: i64,
}

impl CommittedEffectProofFields {
    pub(super) fn encode(&self) -> Vec<u8> {
        let launch_generation = self.launch_generation.to_be_bytes();
        let lifecycle_revision = self.lifecycle_revision.to_be_bytes();
        let credential_fence = self.credential_fence.to_be_bytes();
        let credential_version = self.credential_version.to_be_bytes();
        let lease_expires_at = self.lease_expires_at.to_be_bytes();
        let lease_fence = self.lease_fence.to_be_bytes();
        let effect_started_at = self.effect_started_at.to_be_bytes();
        let effect_expires_at = self.effect_expires_at.to_be_bytes();
        frame(&[
            &self.issuance_mac,
            &self.attempt_id,
            self.provider_id.as_bytes(),
            &launch_generation,
            &lifecycle_revision,
            &credential_fence,
            &credential_version,
            &self.credential_ref_digest,
            &self.lease_owner,
            &lease_expires_at,
            &lease_fence,
            &effect_started_at,
            &effect_expires_at,
        ])
    }
}

fn frame(fields: &[&[u8]]) -> Vec<u8> {
    let capacity = fields.iter().map(|field| 4 + field.len()).sum();
    let mut encoded = Vec::with_capacity(capacity);
    for field in fields {
        let length = u32::try_from(field.len()).expect("proof field length fits u32");
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    encoded
}

use super::*;
use runne_application::provider::{
    ProviderJournalKeyBinding, ProviderLeaseBindingKind, ProviderOperationalTelemetryScope,
};
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
struct OnlineProofKeyring;

impl ProviderJournalKeyring for OnlineProofKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn store_provider_journal_key(
        &self,
        _: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        if key == online_proof_key_ref() {
            ProviderJournalKeyMaterial::new(key, [7; 32])
        } else {
            Err(SecureStoreError::ProviderJournalKeyNotFound)
        }
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }

    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if key == online_proof_key_ref() {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }
}

fn online_proof_key_ref() -> ProviderJournalKeyRef {
    ProviderJournalKeyRef::new([9; 16], 1, [1; 16], 7).unwrap()
}

pub(super) fn arm_online_proof(store: &SqliteProviderExecutionStore) {
    let keyring = OnlineProofKeyring;
    let binding = ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], 7).unwrap();
    store
        .activate_journal_key_with_keyring(&keyring, binding)
        .unwrap();
    store
        .install_online_effect_proof_capability(&keyring, binding)
        .unwrap();
}

pub(super) fn scope() -> ProviderOperationalTelemetryScope {
    ProviderOperationalTelemetryScope::new([1; 16], 7, 11, 13, [2; 32], OBSERVED_AT).unwrap()
}

pub(super) fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "capability-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

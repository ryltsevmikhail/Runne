use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use super::*;
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, SecureStoreError,
};

pub(super) fn openai_profile() -> Arc<SharedTextProviderProfile> {
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    Arc::new(SharedTextProviderProfile::new(Arc::new(
        OpenAiTextProviderProfile::new(profile),
    )))
}

pub(super) fn fixture_adapter_factory() -> Arc<ProviderEffectFactory> {
    Arc::new(|_, _| Err(DaemonError::Bootstrap("fixture adapter unavailable".into())))
}

#[derive(Default)]
pub(super) struct Keyring(Mutex<HashMap<ProviderJournalKeyRef, [u8; 32]>>);

impl ProviderJournalKeyring for Keyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if self.0.lock().unwrap().contains_key(&key) {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.key_ref(), key.with_bytes(|bytes| *bytes));
        Ok(())
    }

    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        let bytes = self
            .0
            .lock()
            .unwrap()
            .get(&key)
            .copied()
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key, bytes)
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }
}

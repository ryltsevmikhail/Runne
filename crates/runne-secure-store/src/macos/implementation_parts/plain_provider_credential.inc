// macOS 27-compatible provider credential storage.
//
// macOS 27 splits executable partition ACL records on save, so the legacy
// exact-ACL provider item cannot be created reliably. This backend uses the
// same login-Keychain generic-password protection as the provider journal key.
// It intentionally implements only the legacy credential store: the daemon is
// forbidden from holding native writer authority, so lifecycle enrollment stays
// on the credential-service path.

use sha2::{Digest, Sha256};

const PLAIN_PROVIDER_SERVICE: &str = "dev.runne.provider-credential.plain.v1";

#[derive(Debug)]
pub struct MacOsPlainProviderCredentialStore {
    service: String,
    account: String,
}

impl MacOsPlainProviderCredentialStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: PLAIN_PROVIDER_SERVICE.to_owned(),
            account: ProviderCredentialId::OpenAi.account().to_owned(),
        }
    }

    fn scoped_provider_store(&self, provider: ProviderCredentialId) -> Self {
        let account = if self.account == ProviderCredentialId::OpenAi.account() {
            provider.account().to_owned()
        } else {
            self.account.clone()
        };
        Self {
            service: self.service.clone(),
            account,
        }
    }

    fn validate_provider(&self, provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        if provider.account() == self.account {
            Ok(())
        } else {
            Err(SecureStoreError::CredentialAccessDenied)
        }
    }

    fn exists(&self) -> Result<bool, SecureStoreError> {
        let _locks =
            acquire_keychain_interaction_locks().map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        runne_macos_keychain_acl::generic_password_exists(&keychain, &self.service, &self.account)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn read_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let _locks =
            acquire_keychain_interaction_locks().map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        match keychain.find_generic_password(&self.service, &self.account) {
            Ok((bytes, _)) => Ok(Some(Zeroizing::new(bytes.as_ref().to_vec()))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(SecureStoreError::ProviderCredentialOperationFailed),
        }
    }

    fn write_bytes(&self, bytes: &[u8]) -> Result<(), SecureStoreError> {
        let _locks =
            acquire_keychain_interaction_locks().map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        keychain
            .set_generic_password(&self.service, &self.account, bytes)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_bytes(&self) -> Result<bool, SecureStoreError> {
        let _locks =
            acquire_keychain_interaction_locks().map_err(|()| SecureStoreError::Unavailable)?;
        let keychain = active_keychain().map_err(|()| SecureStoreError::Unavailable)?;
        match keychain.find_generic_password(&self.service, &self.account) {
            Ok((_, item)) => {
                runne_macos_keychain_acl::delete_item(&item)
                    .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
                Ok(true)
            }
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(_) => Err(SecureStoreError::ProviderCredentialOperationFailed),
        }
    }
}

impl Default for MacOsPlainProviderCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderCredentialStore for MacOsPlainProviderCredentialStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        Ok(if store.exists()? {
            ProviderCredentialStatus::Configured
        } else {
            ProviderCredentialStatus::Missing
        })
    }

    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        credential.with_bytes(|bytes| store.write_bytes(bytes))
    }

    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        let bytes = store
            .read_bytes()?
            .ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        ProviderCredentialMaterial::from_zeroizing(bytes)
    }

    fn load_provider_credential_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        let material = self.load_provider_credential(provider, access)?;
        let revision = material.with_bytes(|bytes| {
            let digest = Sha256::digest(bytes);
            let mut revision = [0_u8; 16];
            revision.copy_from_slice(&digest[..16]);
            if revision == [0; 16] {
                revision[0] = 1;
            }
            crate::ProviderCredentialSourceRevision::new(revision)
        })?;
        Ok(ProviderCredentialSource::new(material, revision))
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        let _ = store.delete_bytes()?;
        Ok(())
    }

    fn migrate_provider_credential_access(
        &self,
        _provider: ProviderCredentialId,
        _current: &ProviderCredentialAccessPolicy,
        _replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

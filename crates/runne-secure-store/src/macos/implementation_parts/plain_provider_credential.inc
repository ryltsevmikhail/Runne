// macOS 27-compatible provider credential storage.
//
// The exact-ACL backend is unusable on macOS 27 by construction: saving the
// item erases the partition ACL, so no cross-process executable ACL survives.
// This backend keeps ONE login-Keychain generic password per provider under
// the same service as the provider journal key. The payload carries the
// installation/writer/reader path binding checked by `provider_credential_binding`.
//
// Delete and overwrite resolve the item by query, never by an ACL identity, so
// a rebuilt CLI can still replace or remove the item it wrote earlier.

const PROVIDER_CREDENTIAL_ACCOUNT_PREFIX: &str = "provider_credential";
const PROVIDER_CREDENTIAL_SERVICE: &str = SERVICE_NAME;

#[derive(Debug)]
pub struct MacOsPlainProviderCredentialStore {
    service: String,
    account: String,
    authority: Option<NativeCredentialAuthority>,
}

impl MacOsPlainProviderCredentialStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: PROVIDER_CREDENTIAL_SERVICE.to_owned(),
            account: ProviderCredentialId::OpenAi.account().to_owned(),
            authority: None,
        }
    }

    #[must_use]
    pub fn new_versioned(authority: NativeCredentialAuthority) -> Self {
        Self {
            authority: Some(authority),
            ..Self::new()
        }
    }

    fn scoped_provider_store(&self, provider: ProviderCredentialId) -> Self {
        let account = if self.account == ProviderCredentialId::OpenAi.account() {
            format!("{PROVIDER_CREDENTIAL_ACCOUNT_PREFIX}:{}", provider.account())
        } else {
            self.account.clone()
        };
        Self {
            service: self.service.clone(),
            account,
            authority: self.authority.clone(),
        }
    }

    fn validate_provider(&self, provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        if self.account == format!("{PROVIDER_CREDENTIAL_ACCOUNT_PREFIX}:{}", provider.account()) {
            Ok(())
        } else {
            Err(SecureStoreError::CredentialAccessDenied)
        }
    }

    fn read_encoded(&self) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        runne_macos_keychain_acl::read_open_generic_password(&self.service, &self.account)
            .map(|value| value.map(Zeroizing::new))
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn write_encoded(
        &self,
        encoded: &[u8],
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let text = std::str::from_utf8(encoded)
            .map_err(|_| SecureStoreError::InvalidProviderCredential)?;
        runne_macos_keychain_acl::write_open_generic_password(&self.service, &self.account, text)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_item(&self) -> Result<bool, SecureStoreError> {
        runne_macos_keychain_acl::delete_open_generic_password(&self.service, &self.account)
            .map(|()| true)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn status_for(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        let Some(encoded) = store.read_encoded()? else {
            return Ok(ProviderCredentialStatus::Missing);
        };
        let decoded = decode_stored_payload(&encoded)?;
        decode_provider_credential(&decoded, access)?;
        Ok(ProviderCredentialStatus::Configured)
    }

    fn load_for(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        let encoded = store
            .read_encoded()?
            .ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let decoded = decode_stored_payload(&encoded)?;
        decode_provider_credential(&decoded, access)
    }

    fn revision_for(
        material: &ProviderCredentialMaterial,
    ) -> Result<ProviderCredentialSourceRevision, SecureStoreError> {
        material.with_bytes(|bytes| {
            let digest = Sha256::digest(bytes);
            let mut revision = [0_u8; 16];
            revision.copy_from_slice(&digest[..16]);
            if revision == [0; 16] {
                revision[0] = 1;
            }
            ProviderCredentialSourceRevision::new(revision)
        })
    }
}

fn decode_stored_payload(encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(Zeroizing::new)
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
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
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.status_for(provider, access)
    }

    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        // Overwrite resolves the existing item by query; a rebuilt writer with
        // a different executable digest still replaces the same logical item.
        use base64::Engine as _;
        let encoded = encode_provider_credential(credential, access)?;
        let text = base64::engine::general_purpose::STANDARD.encode(&encoded);
        store.write_encoded(text.as_bytes(), access)
    }

    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.load_for(provider, access)
    }

    fn load_provider_credential_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        let material = self.load_for(provider, access)?;
        let revision = Self::revision_for(&material)?;
        Ok(ProviderCredentialSource::new(material, revision))
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        // Query-only delete: no ACL identity is compared after a rebuild.
        let _ = store.delete_item()?;
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

#[cfg(any(test, feature = "provider-credential-broker-writer"))]
impl crate::provider_credential::AuthorizedLegacySourceStore
    for MacOsPlainProviderCredentialStore
{
    fn load_authorized_legacy_source(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        let provider = ProviderCredentialId::from_account(read.command().provider().as_str())
            .ok_or(SecureStoreError::ProviderCredentialOperationFailed)?;
        self.load_provider_credential_source(provider, access)
    }
}

include!("plain_provider_credential_versioned.inc");

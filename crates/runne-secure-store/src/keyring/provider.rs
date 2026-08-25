use crate::provider_credential::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialSource, ProviderCredentialStatus, ProviderCredentialStore,
    StoredProviderCredential, generate_provider_credential_source_revision,
};
use crate::{NativeKeyringStore, NativeProviderCredentialVersionStore, SecureStoreError};
use runne_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    CredentialVersionRef, NativeCredentialAuthority, NativeCredentialDeletionProof,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const ACCESS_DIGEST_DOMAIN: &[u8] = b"runne/keyring-provider-access/v1\0";
impl ProviderCredentialStore for NativeKeyringStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        validate_reader_or_writer(access)?;
        let Some(encoded) = Self::read_provider(provider)? else {
            return Ok(ProviderCredentialStatus::Missing);
        };
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        Ok(ProviderCredentialStatus::Configured)
    }
    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        access.validate_writer_current()?;
        access.remeasure()?;
        let revision = generate_provider_credential_source_revision()?;
        let encoded = StoredProviderCredential::encode_with_revision(
            credential,
            access,
            access_digest(access),
            revision,
        )?;
        Self::write_provider(provider, &encoded)
    }
    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        validate_reader_or_writer(access)?;
        let encoded =
            Self::read_provider(provider)?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        Ok(stored.into_material())
    }
    fn load_provider_credential_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        validate_reader_or_writer(access)?;
        let encoded =
            Self::read_provider(provider)?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        stored.into_source()
    }
    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        access.validate_writer_current()?;
        access.remeasure()?;
        Self::delete_provider(provider)
    }
    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        validate_reader_or_writer(current)?;
        replacement.validate_writer_current()?;
        replacement.remeasure()?;
        let encoded =
            Self::read_provider(provider)?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, current)?;
        let revision = stored
            .source_revision()
            .unwrap_or(generate_provider_credential_source_revision()?);
        let material = stored.into_material();
        let replacement_encoded = StoredProviderCredential::encode_with_revision(
            &material,
            replacement,
            access_digest(replacement),
            revision,
        )?;
        Self::write_provider(provider, &replacement_encoded)
    }
}

impl NativeProviderCredentialVersionStore for NativeKeyringStore {
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        provider_id(reference)?;
        validate_reader_or_writer(access)?;
        let Some(encoded) = Self::read_version(reference)?.filter(|bytes| !bytes.is_empty()) else {
            return Ok(ProviderCredentialStatus::Missing);
        };
        validate_stored(&StoredProviderCredential::decode(&encoded)?, access)?;
        Ok(ProviderCredentialStatus::Configured)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let authority = self.version_authority()?;
        let reference = claim.version_ref().clone();
        provider_id(&reference)?;
        access.validate_writer_current()?;
        access.remeasure()?;
        if let Some(existing) = Self::read_version(&reference)? {
            let stored = StoredProviderCredential::decode(&existing)?;
            validate_stored(&stored, access)?;
            if stored.material_matches(credential) {
                return Ok(());
            }
            return Err(SecureStoreError::ProviderCredentialOperationFailed);
        }
        let authorization = authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        if authorization.version_ref() != &reference {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        drop(authorization);
        let encoded = StoredProviderCredential::encode(credential, access, access_digest(access))?;
        Self::write_version(&reference, &encoded)
    }

    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let reference = self
            .version_authority()?
            .authorize_load(capability)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Self::load_provider_version(reference, access)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        // This native GC API does not carry the required writer/reader policy.
        let _ = claim;
        Err(SecureStoreError::CredentialAccessDenied)
    }
}

impl NativeKeyringStore {
    fn version_authority(&self) -> Result<&NativeCredentialAuthority, SecureStoreError> {
        self.version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)
    }

    fn load_provider_version(
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        validate_reader_or_writer(access)?;
        let encoded =
            Self::read_version(reference)?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        Ok(stored.into_material())
    }

    fn read_provider(
        provider: ProviderCredentialId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let (service, account) = provider_key(provider);
        Self::read_secret(&service, &account)
    }

    fn write_provider(
        provider: ProviderCredentialId,
        encoded: &[u8],
    ) -> Result<(), SecureStoreError> {
        let (service, account) = provider_key(provider);
        Self::write_secret(&service, &account, encoded)
    }

    fn delete_provider(provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        let (service, account) = provider_key(provider);
        Self::delete_secret(&service, &account)
    }

    fn read_version(
        reference: &CredentialVersionRef,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let (service, account) = version_key(reference);
        Self::read_secret(&service, &account)
    }

    fn write_version(
        reference: &CredentialVersionRef,
        encoded: &[u8],
    ) -> Result<(), SecureStoreError> {
        let (service, account) = version_key(reference);
        Self::write_secret(&service, &account, encoded)
    }
}

fn provider_key(provider: ProviderCredentialId) -> (String, String) {
    (
        crate::PROVIDER_CREDENTIAL_SERVICE.to_owned(),
        provider.account().to_owned(),
    )
}

fn version_key(reference: &CredentialVersionRef) -> (String, String) {
    let mut ref_hex = String::with_capacity(64);
    for byte in reference.ref_digest() {
        use core::fmt::Write as _;
        let _ = write!(&mut ref_hex, "{byte:02x}");
    }
    (
        format!(
            "{}.version.{}.{}",
            crate::PROVIDER_CREDENTIAL_SERVICE,
            reference.version(),
            ref_hex
        ),
        provider_id(reference).map_or_else(
            |_| "invalid".to_owned(),
            |provider| provider.account().to_owned(),
        ),
    )
}

fn provider_id(reference: &CredentialVersionRef) -> Result<ProviderCredentialId, SecureStoreError> {
    match reference.provider().as_str() {
        "openai" => Ok(ProviderCredentialId::OpenAi),
        "deepseek" => Ok(ProviderCredentialId::DeepSeek),
        _ => Err(SecureStoreError::ProviderCredentialOperationFailed),
    }
}

fn validate_reader_or_writer(
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), SecureStoreError> {
    access.validate_writer_or_reader_current()?;
    access.remeasure()
}

fn validate_stored(
    stored: &StoredProviderCredential,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), SecureStoreError> {
    if !stored.access_matches(access) {
        return Err(SecureStoreError::CredentialAclMigrationRequired);
    }
    if stored.acl_set_digest() != access_digest(access) {
        return Err(SecureStoreError::CredentialAccessDenied);
    }
    Ok(())
}

fn access_digest(access: &ProviderCredentialAccessPolicy) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ACCESS_DIGEST_DOMAIN);
    for identity in [access.writer_identity(), access.reader_identity()] {
        digest.update(identity.executable_sha256());
        digest.update(identity.canonical_path_sha256());
        digest.update(identity.byte_length().to_be_bytes());
    }
    digest.finalize().into()
}

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
use std::fmt::Write as _;
use zeroize::Zeroizing;

mod namespace;
mod versioned;
use namespace::service_prefix;

const ACCESS_DIGEST_DOMAIN: &[u8] = b"runne/keyring-provider-access/v1\0";
impl ProviderCredentialStore for NativeKeyringStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.require_legacy_namespace()?;
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
        self.require_legacy_namespace()?;
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
        self.require_legacy_namespace()?;
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
        self.require_legacy_namespace()?;
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
    ) -> Result<(), SecureStoreError> {
        self.require_legacy_namespace()?;
        Self::delete_provider(provider)
    }

    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.require_legacy_namespace()?;
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

impl NativeKeyringStore {
    pub(crate) fn load_provider_version_for_verification(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.load_provider_version(reference, access)
    }

    fn version_authority(&self) -> Result<&NativeCredentialAuthority, SecureStoreError> {
        self.version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)
    }

    fn load_provider_version(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        validate_reader_or_writer(access)?;
        let encoded = self
            .read_version(reference)?
            .ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        Ok(stored.into_material())
    }

    fn read_provider(
        provider: ProviderCredentialId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let (service, account) = provider_key(provider)?;
        Self::read_secret(&service, &account)
    }

    fn write_provider(
        provider: ProviderCredentialId,
        encoded: &[u8],
    ) -> Result<(), SecureStoreError> {
        let (service, account) = provider_key(provider)?;
        Self::write_secret(&service, &account, encoded)
    }

    fn delete_provider(provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        let (service, account) = provider_key(provider)?;
        Self::delete_secret(&service, &account)
    }

    fn namespaced_version_key(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<(String, String), SecureStoreError> {
        let (service, account) = version_key(reference)?;
        let Some(namespace) = self.provider_namespace else {
            return Ok((service, account));
        };
        if namespace == [0; 16] {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let namespace = namespace
            .iter()
            .fold(String::with_capacity(32), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
        Ok((format!("{service}.cli-host.{namespace}"), account))
    }

    const fn require_legacy_namespace(&self) -> Result<(), SecureStoreError> {
        if self.provider_namespace.is_some() {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        Ok(())
    }

    fn read_version(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        let (service, account) = self.namespaced_version_key(reference)?;
        Self::read_secret(&service, &account)
    }

    fn write_version(
        &self,
        reference: &CredentialVersionRef,
        encoded: &[u8],
    ) -> Result<(), SecureStoreError> {
        let (service, account) = self.namespaced_version_key(reference)?;
        Self::write_secret(&service, &account, encoded)
    }

    fn delete_version_ref(&self, reference: &CredentialVersionRef) -> Result<(), SecureStoreError> {
        let (service, account) = self.namespaced_version_key(reference)?;
        Self::delete_secret(&service, &account)
    }
}

pub(super) fn provider_key(
    provider: ProviderCredentialId,
) -> Result<(String, String), SecureStoreError> {
    Ok((service_prefix()?, provider.account().to_owned()))
}

pub(super) fn version_key(
    reference: &CredentialVersionRef,
) -> Result<(String, String), SecureStoreError> {
    let mut ref_hex = String::with_capacity(64);
    for byte in reference.ref_digest() {
        use core::fmt::Write as _;
        let _ = write!(&mut ref_hex, "{byte:02x}");
    }
    Ok((
        format!(
            "{}.version.{}.{}",
            service_prefix()?,
            reference.version(),
            ref_hex
        ),
        provider_id(reference).map_or_else(
            |_| "invalid".to_owned(),
            |provider| provider.account().to_owned(),
        ),
    ))
}

fn provider_id(reference: &CredentialVersionRef) -> Result<ProviderCredentialId, SecureStoreError> {
    ProviderCredentialId::from_account(reference.provider().as_str())
        .ok_or(SecureStoreError::ProviderCredentialOperationFailed)
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

#[cfg(test)]
#[path = "provider/cli_namespace_tests.rs"]
mod cli_namespace_tests;

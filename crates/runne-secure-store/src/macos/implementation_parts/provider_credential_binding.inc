// Bound login-Keychain provider credential payload (macOS 27+).
//
// macOS 27 strips exact executable partition ACLs on save, so the credential
// cannot be protected by an ACL there. The item is still one login-Keychain
// generic password; the payload records the installation and path identities
// that wrote and may read it. The reader re-derives and checks them before
// releasing material. The binding survives a rebuild at the same install path,
// which an executable-content digest would not.

use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt as _;

const PROVIDER_CREDENTIAL_BINDING_MAGIC: &[u8; 4] = b"RCP1";
const PROVIDER_CREDENTIAL_BINDING_DOMAIN: &[u8] = b"runne/provider-credential/binding/v1\0";
const PROVIDER_CREDENTIAL_INSTALL_DOMAIN: &[u8] = b"runne/provider-credential/install/v1\0";
const PROVIDER_CREDENTIAL_WRITER_DOMAIN: &[u8] = b"runne/provider-credential/writer/v1\0";
const PROVIDER_CREDENTIAL_READER_DOMAIN: &[u8] = b"runne/provider-credential/reader/v1\0";
const PROVIDER_CREDENTIAL_BINDING_HASH_BYTES: usize = 12;
const PROVIDER_CREDENTIAL_BINDING_HEADER: usize =
    PROVIDER_CREDENTIAL_BINDING_MAGIC.len() + (3 * PROVIDER_CREDENTIAL_BINDING_HASH_BYTES) + 2;

struct ProviderCredentialBinding {
    installation: [u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES],
    writer: [u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES],
    reader: [u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES],
}

impl ProviderCredentialBinding {
    fn from_access(access: &ProviderCredentialAccessPolicy) -> Result<Self, SecureStoreError> {
        let installation = access
            .writer_path()
            .parent()
            .ok_or(SecureStoreError::CredentialIdentityMismatch)?;
        Ok(Self {
            installation: identity_hash(PROVIDER_CREDENTIAL_INSTALL_DOMAIN, installation)?,
            writer: identity_hash(PROVIDER_CREDENTIAL_WRITER_DOMAIN, access.writer_path())?,
            reader: identity_hash(PROVIDER_CREDENTIAL_READER_DOMAIN, access.reader_path())?,
        })
    }

    fn verify(&self, access: &ProviderCredentialAccessPolicy) -> Result<(), SecureStoreError> {
        let expected = Self::from_access(access)?;
        if self.installation != expected.installation
            || self.writer != expected.writer
            || self.reader != expected.reader
        {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        Ok(())
    }
}

fn identity_hash(
    domain: &[u8],
    path: &std::path::Path,
) -> Result<[u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES], SecureStoreError> {
    let bytes = path.as_os_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_CREDENTIAL_BINDING_DOMAIN);
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut value = [0_u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES];
    value.copy_from_slice(&digest[..PROVIDER_CREDENTIAL_BINDING_HASH_BYTES]);
    Ok(value)
}

fn encode_provider_credential(
    material: &ProviderCredentialMaterial,
    access: &ProviderCredentialAccessPolicy,
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    let binding = ProviderCredentialBinding::from_access(access)?;
    let length = material.with_bytes(<[u8]>::len);
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        PROVIDER_CREDENTIAL_BINDING_HEADER + length,
    ));
    encoded.extend_from_slice(PROVIDER_CREDENTIAL_BINDING_MAGIC);
    encoded.extend_from_slice(&binding.installation);
    encoded.extend_from_slice(&binding.writer);
    encoded.extend_from_slice(&binding.reader);
    encoded.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| SecureStoreError::InvalidProviderCredential)?
            .to_be_bytes(),
    );
    material.with_bytes(|bytes| encoded.extend_from_slice(bytes));
    Ok(encoded)
}

fn decode_provider_credential(
    encoded: &[u8],
    access: &ProviderCredentialAccessPolicy,
) -> Result<ProviderCredentialMaterial, SecureStoreError> {
    if encoded.len() < PROVIDER_CREDENTIAL_BINDING_HEADER
        || &encoded[..PROVIDER_CREDENTIAL_BINDING_MAGIC.len()] != PROVIDER_CREDENTIAL_BINDING_MAGIC
    {
        return Err(SecureStoreError::CorruptProviderCredential);
    }
    let mut offset = PROVIDER_CREDENTIAL_BINDING_MAGIC.len();
    let binding = ProviderCredentialBinding {
        installation: take_hash(encoded, &mut offset)?,
        writer: take_hash(encoded, &mut offset)?,
        reader: take_hash(encoded, &mut offset)?,
    };
    binding.verify(access)?;
    let length = usize::from(u16::from_be_bytes(take_2(encoded, &mut offset)?));
    let end = offset
        .checked_add(length)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    if length == 0 || end != encoded.len() {
        return Err(SecureStoreError::CorruptProviderCredential);
    }
    ProviderCredentialMaterial::from_zeroizing(Zeroizing::new(encoded[offset..].to_vec()))
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
}

fn take_hash(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; PROVIDER_CREDENTIAL_BINDING_HASH_BYTES], SecureStoreError> {
    let end = offset
        .checked_add(PROVIDER_CREDENTIAL_BINDING_HASH_BYTES)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
}

fn take_2(encoded: &[u8], offset: &mut usize) -> Result<[u8; 2], SecureStoreError> {
    let end = offset
        .checked_add(2)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
}

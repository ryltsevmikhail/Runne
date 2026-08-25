use rand::{RngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

use runne_provider::{
    NativeSecretRef, SecureStoreError as TailStoreError, TailBinding, WithheldTailStore,
};

use crate::keyring::{KEYRING_LOCK, NativeKeyringStore};

const SERVICE: &str = "dev.runne.provider-withheld-tail.v1";
const MAGIC: &[u8; 8] = b"GCWTLV1\0";
const MANIFEST_MAGIC: &[u8; 8] = b"GCWTLM1\0";

impl WithheldTailStore for NativeKeyringStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        let _guard = KEYRING_LOCK
            .lock()
            .map_err(|_| TailStoreError::Unavailable)?;
        let mut id = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| TailStoreError::Unavailable)?;
        if id == [0; 16] {
            return Err(TailStoreError::Unavailable);
        }
        let reference = NativeSecretRef::new(id, 1, binding.digest())?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(40 + bytes.len()));
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(reference.binding_digest());
        encoded.extend_from_slice(&bytes);
        let (service, account) = tail_key(self, reference);
        Self::write_secret(&service, &account, &encoded)
            .map_err(|_| TailStoreError::Unavailable)?;
        let mut manifest = read_manifest(self, binding)?;
        manifest.push(reference);
        write_manifest(self, binding, &manifest)?;
        Ok(reference)
    }

    fn load_tail(
        &self,
        reference: &NativeSecretRef,
        binding: TailBinding,
    ) -> Result<Zeroizing<Vec<u8>>, TailStoreError> {
        if reference.binding_digest() != &binding.digest() {
            return Err(TailStoreError::BindingMismatch);
        }
        let (service, account) = tail_key(self, *reference);
        let encoded = Self::read_secret(&service, &account)
            .map_err(|_| TailStoreError::Unavailable)?
            .ok_or(TailStoreError::NotFound)?;
        if encoded.len() < 40
            || encoded.get(..8) != Some(MAGIC)
            || encoded.get(8..40) != Some(reference.binding_digest().as_slice())
        {
            return Err(TailStoreError::Corrupt);
        }
        Ok(Zeroizing::new(encoded[40..].to_vec()))
    }

    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), TailStoreError> {
        let (service, account) = tail_key(self, *reference);
        Self::delete_secret(&service, &account).map_err(|_| TailStoreError::Unavailable)
    }

    fn purge_orphaned_tails(
        &self,
        binding: TailBinding,
        retained: Option<NativeSecretRef>,
    ) -> Result<(), TailStoreError> {
        let _guard = KEYRING_LOCK
            .lock()
            .map_err(|_| TailStoreError::Unavailable)?;
        let manifest = read_manifest(self, binding)?;
        let mut remaining = Vec::new();
        for reference in manifest {
            if Some(reference) == retained {
                remaining.push(reference);
                continue;
            }
            let (service, account) = tail_key(self, reference);
            Self::delete_secret(&service, &account).map_err(|_| TailStoreError::Unavailable)?;
        }
        write_manifest(self, binding, &remaining)
    }
}

fn tail_key(store: &NativeKeyringStore, reference: NativeSecretRef) -> (String, String) {
    (
        SERVICE.to_owned(),
        format!(
            "{}:tail:{}:{}",
            store.profile_id,
            hex(reference.id()),
            reference.version()
        ),
    )
}

fn manifest_key(store: &NativeKeyringStore, binding: TailBinding) -> (String, String) {
    (
        SERVICE.to_owned(),
        format!(
            "{}:manifest:{}",
            store.profile_id,
            hex(binding.attempt_id().as_bytes())
        ),
    )
}

fn read_manifest(
    store: &NativeKeyringStore,
    binding: TailBinding,
) -> Result<Vec<NativeSecretRef>, TailStoreError> {
    let (service, account) = manifest_key(store, binding);
    let Some(encoded) = NativeKeyringStore::read_secret(&service, &account)
        .map_err(|_| TailStoreError::Unavailable)?
    else {
        return Ok(Vec::new());
    };
    if encoded.len() < 12 || encoded.get(..8) != Some(MANIFEST_MAGIC.as_slice()) {
        return Err(TailStoreError::Corrupt);
    }
    let count = usize::try_from(u32::from_be_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| TailStoreError::Corrupt)?,
    ))
    .map_err(|_| TailStoreError::Corrupt)?;
    let expected = 12usize
        .checked_add(count.checked_mul(52).ok_or(TailStoreError::Corrupt)?)
        .ok_or(TailStoreError::Corrupt)?;
    if expected != encoded.len() {
        return Err(TailStoreError::Corrupt);
    }
    (0..count)
        .map(|index| {
            let offset = 12 + index * 52;
            let id = encoded[offset..offset + 16]
                .try_into()
                .map_err(|_| TailStoreError::Corrupt)?;
            let version = u32::from_be_bytes(
                encoded[offset + 16..offset + 20]
                    .try_into()
                    .map_err(|_| TailStoreError::Corrupt)?,
            );
            let digest = encoded[offset + 20..offset + 52]
                .try_into()
                .map_err(|_| TailStoreError::Corrupt)?;
            NativeSecretRef::new(id, version, digest).map_err(|_| TailStoreError::Corrupt)
        })
        .collect()
}

fn write_manifest(
    store: &NativeKeyringStore,
    binding: TailBinding,
    references: &[NativeSecretRef],
) -> Result<(), TailStoreError> {
    let count = u32::try_from(references.len()).map_err(|_| TailStoreError::Unavailable)?;
    let mut encoded = Vec::with_capacity(12 + references.len() * 52);
    encoded.extend_from_slice(MANIFEST_MAGIC);
    encoded.extend_from_slice(&count.to_be_bytes());
    for reference in references {
        encoded.extend_from_slice(&reference.id());
        encoded.extend_from_slice(&reference.version().to_be_bytes());
        encoded.extend_from_slice(reference.binding_digest());
    }
    let (service, account) = manifest_key(store, binding);
    NativeKeyringStore::write_secret(&service, &account, &encoded)
        .map_err(|_| TailStoreError::Unavailable)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        use core::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

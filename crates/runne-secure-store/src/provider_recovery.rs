//! Native encrypted storage adapter for provider scanner withheld tails.

#[cfg(any(
    target_os = "macos",
    not(any(target_os = "linux", target_os = "windows"))
))]
use runne_provider::{
    NativeSecretRef, SecureStoreError as TailStoreError, TailBinding, WithheldTailStore,
};
#[cfg(any(
    target_os = "macos",
    not(any(target_os = "linux", target_os = "windows"))
))]
use zeroize::Zeroizing;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub use crate::StubStore as NativeWithheldTailStore;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl WithheldTailStore for crate::StubStore {
    fn put_tail(
        &self,
        _binding: TailBinding,
        _bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        Err(TailStoreError::Unavailable)
    }

    fn load_tail(
        &self,
        _reference: &NativeSecretRef,
        _binding: TailBinding,
    ) -> Result<Zeroizing<Vec<u8>>, TailStoreError> {
        Err(TailStoreError::Unavailable)
    }

    fn delete_tail(&self, _reference: &NativeSecretRef) -> Result<(), TailStoreError> {
        Err(TailStoreError::Unavailable)
    }

    fn purge_orphaned_tails(
        &self,
        _binding: TailBinding,
        _retained: Option<NativeSecretRef>,
    ) -> Result<(), TailStoreError> {
        Err(TailStoreError::Unavailable)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use crate::NativeKeyringStore as NativeWithheldTailStore;

#[cfg(target_os = "macos")]
pub use crate::MacOsKeychainStore as NativeWithheldTailStore;

#[cfg(target_os = "macos")]
const SERVICE: &str = "runne-provider-withheld-tail-v1";
#[cfg(target_os = "macos")]
const MAGIC: &[u8; 8] = b"GCWTLV1\0";
#[cfg(target_os = "macos")]
const MANIFEST_MAGIC: &[u8; 8] = b"GCWTLM1\0";
#[cfg(target_os = "macos")]
impl WithheldTailStore for crate::MacOsKeychainStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        use rand::{RngCore as _, rngs::OsRng};
        let _keychain_locks = crate::macos::acquire_keychain_interaction_locks()
            .map_err(|()| TailStoreError::Unavailable)?;
        let mut id = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| TailStoreError::Unavailable)?;
        if id == [0; 16] {
            return Err(TailStoreError::Unavailable);
        }
        let reference = NativeSecretRef::new(id, 1, binding.digest())?;
        register_tail(self, binding, reference)?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(40 + bytes.len()));
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(reference.binding_digest());
        encoded.extend_from_slice(&bytes);
        security_framework::passwords::set_generic_password(
            &tail_service(self),
            &tail_account(reference),
            &encoded,
        )
        .map_err(|_| TailStoreError::Unavailable)?;
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
        let _keychain_locks = crate::macos::acquire_keychain_interaction_locks()
            .map_err(|()| TailStoreError::Unavailable)?;
        let encoded = Zeroizing::new(
            security_framework::passwords::get_generic_password(
                &tail_service(self),
                &tail_account(*reference),
            )
            .map_err(|error| {
                if error.code() == -25_300 {
                    TailStoreError::NotFound
                } else {
                    TailStoreError::Unavailable
                }
            })?,
        );
        if encoded.len() < 40
            || &encoded[..8] != MAGIC
            || &encoded[8..40] != reference.binding_digest()
        {
            return Err(TailStoreError::Corrupt);
        }
        Ok(Zeroizing::new(encoded[40..].to_vec()))
    }

    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), TailStoreError> {
        let _keychain_locks = crate::macos::acquire_keychain_interaction_locks()
            .map_err(|()| TailStoreError::Unavailable)?;
        match security_framework::passwords::delete_generic_password(
            &tail_service(self),
            &tail_account(*reference),
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25_300 => Ok(()),
            Err(_) => Err(TailStoreError::Unavailable),
        }
    }

    fn purge_orphaned_tails(
        &self,
        binding: TailBinding,
        retained: Option<NativeSecretRef>,
    ) -> Result<(), TailStoreError> {
        let _keychain_locks = crate::macos::acquire_keychain_interaction_locks()
            .map_err(|()| TailStoreError::Unavailable)?;
        purge_registered_tails(self, binding, retained)
    }
}

#[cfg(target_os = "macos")]
fn tail_service(store: &crate::MacOsKeychainStore) -> String {
    format!("{SERVICE}:{}", store.provider_recovery_profile_scope())
}

#[cfg(target_os = "macos")]
fn tail_account(reference: NativeSecretRef) -> String {
    let mut account = String::from("tail:");
    for byte in reference.id() {
        use core::fmt::Write as _;
        let _ = write!(&mut account, "{byte:02x}");
    }
    account.push(':');
    account.push_str(&reference.version().to_string());
    account
}

#[cfg(target_os = "macos")]
fn manifest_account(binding: TailBinding) -> String {
    let mut account = String::from("manifest:");
    for byte in binding.attempt_id().as_bytes() {
        use core::fmt::Write as _;
        let _ = write!(&mut account, "{byte:02x}");
    }
    account
}

#[cfg(target_os = "macos")]
fn register_tail(
    store: &crate::MacOsKeychainStore,
    binding: TailBinding,
    reference: NativeSecretRef,
) -> Result<(), TailStoreError> {
    let mut references = read_manifest(store, binding)?;
    if !references.contains(&reference) {
        references.push(reference);
    }
    write_manifest(store, binding, &references)
}

#[cfg(target_os = "macos")]
fn purge_registered_tails(
    store: &crate::MacOsKeychainStore,
    binding: TailBinding,
    retained: Option<NativeSecretRef>,
) -> Result<(), TailStoreError> {
    for reference in read_manifest(store, binding)? {
        if Some(reference) == retained {
            continue;
        }
        match security_framework::passwords::delete_generic_password(
            &tail_service(store),
            &tail_account(reference),
        ) {
            Ok(()) => {}
            Err(error) if error.code() == -25_300 => {}
            Err(_) => return Err(TailStoreError::Unavailable),
        }
    }
    let retained = retained.into_iter().collect::<Vec<_>>();
    write_manifest(store, binding, &retained)
}

#[cfg(target_os = "macos")]
fn read_manifest(
    store: &crate::MacOsKeychainStore,
    binding: TailBinding,
) -> Result<Vec<NativeSecretRef>, TailStoreError> {
    let bytes = match security_framework::passwords::get_generic_password(
        &tail_service(store),
        &manifest_account(binding),
    ) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.code() == -25_300 => return Ok(Vec::new()),
        Err(_) => return Err(TailStoreError::Unavailable),
    };
    if bytes.len() < 8 || &bytes[..8] != MANIFEST_MAGIC || (bytes.len() - 8) % 52 != 0 {
        return Err(TailStoreError::Corrupt);
    }
    bytes[8..]
        .chunks_exact(52)
        .map(|chunk| {
            let id = chunk[..16]
                .try_into()
                .map_err(|_| TailStoreError::Corrupt)?;
            let version = u32::from_be_bytes(
                chunk[16..20]
                    .try_into()
                    .map_err(|_| TailStoreError::Corrupt)?,
            );
            let digest = chunk[20..52]
                .try_into()
                .map_err(|_| TailStoreError::Corrupt)?;
            NativeSecretRef::new(id, version, digest)
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn write_manifest(
    store: &crate::MacOsKeychainStore,
    binding: TailBinding,
    references: &[NativeSecretRef],
) -> Result<(), TailStoreError> {
    let account = manifest_account(binding);
    if references.is_empty() {
        return match security_framework::passwords::delete_generic_password(
            &tail_service(store),
            &account,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25_300 => Ok(()),
            Err(_) => Err(TailStoreError::Unavailable),
        };
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(8 + references.len() * 52));
    bytes.extend_from_slice(MANIFEST_MAGIC);
    for reference in references {
        bytes.extend_from_slice(&reference.id());
        bytes.extend_from_slice(&reference.version().to_be_bytes());
        bytes.extend_from_slice(reference.binding_digest());
    }
    security_framework::passwords::set_generic_password(&tail_service(store), &account, &bytes)
        .map_err(|_| TailStoreError::Unavailable)
}

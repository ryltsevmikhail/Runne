//! Native encrypted storage adapter for provider scanner withheld tails.

use gocode_provider::{
    NativeSecretRef, SecureStoreError as TailStoreError, TailBinding, WithheldTailStore,
};
use zeroize::Zeroizing;

#[cfg(not(target_os = "macos"))]
pub use crate::StubStore as NativeWithheldTailStore;

#[cfg(not(target_os = "macos"))]
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
}

#[cfg(target_os = "macos")]
pub use crate::MacOsKeychainStore as NativeWithheldTailStore;

#[cfg(target_os = "macos")]
const SERVICE: &str = "gocode-provider-withheld-tail-v1";
#[cfg(target_os = "macos")]
const MAGIC: &[u8; 8] = b"GCWTLV1\0";

#[cfg(target_os = "macos")]
impl WithheldTailStore for crate::MacOsKeychainStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, TailStoreError> {
        use rand::{RngCore as _, rngs::OsRng};
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
        security_framework::passwords::set_generic_password(
            SERVICE,
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
        let encoded = Zeroizing::new(
            security_framework::passwords::get_generic_password(SERVICE, &tail_account(*reference))
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

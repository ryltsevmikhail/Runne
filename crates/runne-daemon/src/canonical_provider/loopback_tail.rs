use std::collections::HashMap;
use std::sync::Mutex;

use runne_provider::{NativeSecretRef, SecureStoreError, TailBinding, WithheldTailStore};
use zeroize::Zeroizing;

type Tail = (TailBinding, Zeroizing<Vec<u8>>);

/// Process-local backend restricted to the explicit loopback dependency capsule.
#[derive(Default)]
pub(super) struct LoopbackWithheldTailStore {
    next: Mutex<u64>,
    tails: Mutex<HashMap<NativeSecretRef, Tail>>,
}

impl WithheldTailStore for LoopbackWithheldTailStore {
    fn put_tail(
        &self,
        binding: TailBinding,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<NativeSecretRef, SecureStoreError> {
        let mut next = self
            .next
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        *next = next.checked_add(1).ok_or(SecureStoreError::Unavailable)?;
        let mut id = [0_u8; 16];
        id[8..].copy_from_slice(&next.to_be_bytes());
        let reference = NativeSecretRef::new(id, 1, binding.digest())?;
        self.tails
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?
            .insert(reference, (binding, bytes));
        Ok(reference)
    }

    fn load_tail(
        &self,
        reference: &NativeSecretRef,
        binding: TailBinding,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        let tails = self
            .tails
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        let (stored, bytes) = tails.get(reference).ok_or(SecureStoreError::NotFound)?;
        if *stored != binding || reference.binding_digest() != &binding.digest() {
            return Err(SecureStoreError::BindingMismatch);
        }
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), SecureStoreError> {
        self.tails
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?
            .remove(reference);
        Ok(())
    }

    fn purge_orphaned_tails(
        &self,
        binding: TailBinding,
        retained: Option<NativeSecretRef>,
    ) -> Result<(), SecureStoreError> {
        self.tails
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?
            .retain(|reference, (stored, _)| {
                stored.attempt_id() != binding.attempt_id() || Some(*reference) == retained
            });
        Ok(())
    }
}

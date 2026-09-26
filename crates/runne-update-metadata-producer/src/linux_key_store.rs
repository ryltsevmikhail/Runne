use crate::input::UpdatePublicKeyManifest;
use crate::issuer::ProducerError;
use crate::key_store::{KeySlot, UpdateSigningKeyStore};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore as _;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use zeroize::Zeroizing;

pub trait SecretPort {
    fn read(&self, slot: KeySlot) -> Result<Option<Zeroizing<Vec<u8>>>, ProducerError>;
    fn create(&self, slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError>;
    fn remove_if_value(
        &self,
        slot: KeySlot,
        identity: &str,
        expected: &[u8],
    ) -> Result<(), ProducerError>;
}

impl<T: SecretPort> SecretPort for &T {
    fn read(&self, slot: KeySlot) -> Result<Option<Zeroizing<Vec<u8>>>, ProducerError> {
        (**self).read(slot)
    }
    fn create(&self, slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError> {
        (**self).create(slot, seed)
    }
    fn remove_if_value(
        &self,
        slot: KeySlot,
        identity: &str,
        expected: &[u8],
    ) -> Result<(), ProducerError> {
        (**self).remove_if_value(slot, identity, expected)
    }
}

pub struct NativeSecretPort;
impl SecretPort for NativeSecretPort {
    fn read(&self, slot: KeySlot) -> Result<Option<Zeroizing<Vec<u8>>>, ProducerError> {
        crate::linux_secret_service::read(slot).map(|value| value.map(Zeroizing::new))
    }
    fn create(&self, slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError> {
        crate::linux_secret_service::create(slot, seed)
    }
    fn remove_if_value(
        &self,
        slot: KeySlot,
        identity: &str,
        expected: &[u8],
    ) -> Result<(), ProducerError> {
        crate::linux_secret_service::remove_if_value(slot, identity, expected)
    }
}

pub struct SecretServiceStore<P = NativeSecretPort> {
    port: P,
}

impl SecretServiceStore<NativeSecretPort> {
    pub fn open() -> Result<Self, ProducerError> {
        let store = Self {
            port: NativeSecretPort,
        };
        for slot in KeySlot::ALL {
            store.port.read(slot)?.ok_or(ProducerError::KeyStore)?;
        }
        Ok(store)
    }
}

impl<P: SecretPort> SecretServiceStore<P> {
    fn seed(&self, slot: KeySlot) -> Result<Zeroizing<Vec<u8>>, ProducerError> {
        let seed = self.port.read(slot)?.ok_or(ProducerError::KeyStore)?;
        if seed.len() != 32 {
            return Err(ProducerError::KeyStore);
        }
        Ok(seed)
    }
    fn manifest(&self) -> Result<UpdatePublicKeyManifest, ProducerError> {
        Ok(UpdatePublicKeyManifest {
            schema_version: 1,
            root_a_id: KeySlot::RootA.key_id().into(),
            root_a_hex: hex::encode(self.public_key(KeySlot::RootA)?),
            root_b_id: KeySlot::RootB.key_id().into(),
            root_b_hex: hex::encode(self.public_key(KeySlot::RootB)?),
            root_c_id: KeySlot::RootC.key_id().into(),
            root_c_hex: hex::encode(self.public_key(KeySlot::RootC)?),
            snapshot_id: KeySlot::Snapshot.key_id().into(),
            snapshot_hex: hex::encode(self.public_key(KeySlot::Snapshot)?),
            timestamp_id: KeySlot::Timestamp.key_id().into(),
            timestamp_hex: hex::encode(self.public_key(KeySlot::Timestamp)?),
        })
    }
}

impl<P: SecretPort> UpdateSigningKeyStore for SecretServiceStore<P> {
    fn public_key(&self, slot: KeySlot) -> Result<[u8; 32], ProducerError> {
        let stored_seed = self.seed(slot)?;
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(stored_seed.as_slice()).map_err(|_| ProducerError::KeyStore)?,
        );
        Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }
    fn sign(&self, slot: KeySlot, bytes: &[u8]) -> Result<[u8; 64], ProducerError> {
        let stored_seed = self.seed(slot)?;
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(stored_seed.as_slice()).map_err(|_| ProducerError::KeyStore)?,
        );
        Ok(SigningKey::from_bytes(&seed).sign(bytes).to_bytes())
    }
}

#[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
pub fn initialize_and_publish(
    manifest_path: &Path,
    publish: impl FnOnce(&Path, &UpdatePublicKeyManifest) -> Result<(), ProducerError>,
) -> Result<(), ProducerError> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").ok_or(ProducerError::KeyStore)?;
    let runtime_dir = Path::new(&runtime_dir);
    with_init_lock(runtime_dir, || {
        initialize_transaction(&NativeSecretPort, |manifest| {
            publish(manifest_path, manifest)
        })
    })
}

#[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
fn with_init_lock<T>(
    runtime_dir: &Path,
    operation: impl FnOnce() -> Result<T, ProducerError>,
) -> Result<T, ProducerError> {
    if !runtime_dir.is_absolute() {
        return Err(ProducerError::KeyStore);
    }
    let directory = fs::symlink_metadata(runtime_dir).map_err(|_| ProducerError::KeyStore)?;
    let process_uid = fs::metadata("/proc/self")
        .map_err(|_| ProducerError::KeyStore)?
        .uid();
    if directory.file_type().is_symlink()
        || !directory.is_dir()
        || directory.uid() != process_uid
        || directory.mode() & 0o077 != 0
    {
        return Err(ProducerError::KeyStore);
    }
    let lock_path = runtime_dir.join("runne-update-metadata-producer-init.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(0x20000) // O_NOFOLLOW
        .open(lock_path)
        .map_err(|_| ProducerError::KeyStore)?;
    let metadata = lock.metadata().map_err(|_| ProducerError::KeyStore)?;
    if !metadata.is_file()
        || metadata.uid() != process_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(ProducerError::KeyStore);
    }
    lock.lock().map_err(|_| ProducerError::KeyStore)?;
    operation()
}

#[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
fn initialize_transaction(
    port: &impl SecretPort,
    publish: impl FnOnce(&UpdatePublicKeyManifest) -> Result<(), ProducerError>,
) -> Result<(), ProducerError> {
    for slot in KeySlot::ALL {
        if port.read(slot)?.is_some() {
            return Err(ProducerError::KeyStore);
        }
    }
    let mut created: Vec<(KeySlot, String, Zeroizing<[u8; 32]>)> = Vec::new();
    for slot in KeySlot::ALL {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        let identity = match port.create(slot, seed.as_ref()) {
            Ok(identity) => identity,
            Err(error) => {
                if rollback(port, &created).is_err() {
                    return Err(ProducerError::KeyStore);
                }
                return Err(error);
            }
        };
        created.push((slot, identity, seed));
    }
    match (SecretServiceStore { port }).manifest() {
        Ok(manifest) => match publish(&manifest) {
            Ok(()) => Ok(()),
            Err(error) => {
                rollback(port, &created).map_or(Err(ProducerError::KeyStore), |()| Err(error))
            }
        },
        Err(error) => {
            rollback(port, &created).map_or(Err(ProducerError::KeyStore), |()| Err(error))
        }
    }
}

#[cfg(all(debug_assertions, feature = "dev-keyset-init"))]
fn rollback(
    port: &impl SecretPort,
    created: &[(KeySlot, String, Zeroizing<[u8; 32]>)],
) -> Result<(), ProducerError> {
    let mut failed = false;
    for (slot, identity, seed) in created.iter().rev() {
        if port
            .remove_if_value(*slot, identity, seed.as_ref())
            .is_err()
        {
            failed = true;
        }
    }
    if failed {
        Err(ProducerError::KeyStore)
    } else {
        Ok(())
    }
}

#[cfg(all(test, debug_assertions, feature = "dev-keyset-init"))]
#[path = "linux_key_store_tests.rs"]
mod tests;

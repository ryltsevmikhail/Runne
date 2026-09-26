use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

use super::*;
use ed25519_dalek::Verifier as _;

#[derive(Default)]
struct FakePort {
    values: RefCell<Vec<(KeySlot, Vec<u8>)>>,
    fail_at: Option<KeySlot>,
}

impl SecretPort for FakePort {
    fn read(&self, slot: KeySlot) -> Result<Option<Zeroizing<Vec<u8>>>, ProducerError> {
        Ok(self
            .values
            .borrow()
            .iter()
            .find(|(key, _)| *key == slot)
            .map(|(_, value)| Zeroizing::new(value.clone())))
    }
    fn create(&self, slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError> {
        if self.fail_at == Some(slot) || self.read(slot)?.is_some() {
            return Err(ProducerError::KeyStore);
        }
        self.values.borrow_mut().push((slot, seed.to_vec()));
        Ok(slot.account().into())
    }
    fn remove_if_value(
        &self,
        slot: KeySlot,
        identity: &str,
        expected: &[u8],
    ) -> Result<(), ProducerError> {
        if identity != slot.account() {
            return Err(ProducerError::KeyStore);
        }
        let mut values = self.values.borrow_mut();
        if values
            .iter()
            .any(|(key, value)| *key == slot && value.as_slice() != expected)
        {
            return Err(ProducerError::KeyStore);
        }
        values.retain(|(key, _)| *key != slot);
        Ok(())
    }
}

fn run_init(
    port: &impl SecretPort,
    runtime_dir: &Path,
    publish: impl FnOnce(&UpdatePublicKeyManifest) -> Result<(), ProducerError>,
) -> Result<(), ProducerError> {
    fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| ProducerError::KeyStore)?;
    with_init_lock(runtime_dir, || initialize_transaction(port, publish))
}

#[test]
fn duplicate_slot_refuses_without_mutation() {
    let port = FakePort::default();
    port.values.borrow_mut().push((KeySlot::RootA, vec![7; 32]));
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        run_init(&port, directory.path(), |_| Ok(())),
        Err(ProducerError::KeyStore)
    ));
    assert_eq!(port.values.borrow().len(), 1);
}

#[test]
fn partial_failure_rolls_back_only_created_slots() {
    let port = FakePort {
        fail_at: Some(KeySlot::RootC),
        ..FakePort::default()
    };
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        run_init(&port, directory.path(), |_| Ok(())),
        Err(ProducerError::KeyStore)
    ));
    assert!(port.values.borrow().is_empty());
}

#[test]
fn malformed_seed_is_rejected() {
    let port = FakePort::default();
    port.values.borrow_mut().push((KeySlot::RootA, vec![1; 31]));
    let store = SecretServiceStore { port };
    assert_eq!(
        store.public_key(KeySlot::RootA),
        Err(ProducerError::KeyStore)
    );
}

#[test]
fn generated_manifest_contains_public_keys_only() {
    let port = FakePort::default();
    let directory = tempfile::tempdir().unwrap();
    let manifest = RefCell::new(None);
    run_init(&port, directory.path(), |created| {
        *manifest.borrow_mut() = Some(created.clone());
        Ok(())
    })
    .unwrap();
    let manifest = manifest.into_inner().unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(!json.contains("seed"));
    assert_eq!(manifest.root_a_hex.len(), 64);
    let store = SecretServiceStore { port };
    let message = b"manifest signature check";
    let signature = store.sign(KeySlot::RootA, message).unwrap();
    let public =
        ed25519_dalek::VerifyingKey::from_bytes(&store.public_key(KeySlot::RootA).unwrap())
            .unwrap();
    public
        .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
}

#[test]
fn failed_publication_rolls_back_keyset_for_retry() {
    let port = FakePort::default();
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        run_init(&port, directory.path(), |_| Err(ProducerError::Output)),
        Err(ProducerError::Output)
    );
    assert!(port.values.borrow().is_empty());
    run_init(&port, directory.path(), |_| Ok(())).unwrap();
    assert_eq!(port.values.borrow().len(), KeySlot::ALL.len());
}

#[derive(Clone, Default)]
struct OverwritingPort(Arc<Mutex<StoredValues>>);

type StoredValues = Vec<(KeySlot, Vec<u8>)>;

impl SecretPort for OverwritingPort {
    fn read(&self, slot: KeySlot) -> Result<Option<Zeroizing<Vec<u8>>>, ProducerError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|(key, _)| *key == slot)
            .map(|(_, value)| Zeroizing::new(value.clone())))
    }
    fn create(&self, slot: KeySlot, seed: &[u8]) -> Result<String, ProducerError> {
        let mut values = self.0.lock().unwrap();
        values.retain(|(key, _)| *key != slot);
        values.push((slot, seed.to_vec()));
        drop(values);
        Ok(slot.account().into())
    }
    fn remove_if_value(
        &self,
        slot: KeySlot,
        identity: &str,
        expected: &[u8],
    ) -> Result<(), ProducerError> {
        if identity != slot.account() {
            return Err(ProducerError::KeyStore);
        }
        let mut values = self.0.lock().unwrap();
        if values
            .iter()
            .any(|(key, value)| *key == slot && value.as_slice() != expected)
        {
            return Err(ProducerError::KeyStore);
        }
        values.retain(|(key, _)| *key != slot);
        drop(values);
        Ok(())
    }
}

#[test]
fn concurrent_initializers_serialize_before_overwriting_backend_create() {
    let port = OverwritingPort::default();
    let directory = tempfile::tempdir().unwrap();
    let runtime_dir = directory.path().to_owned();
    let first_port = port.clone();
    let first_dir = runtime_dir.clone();
    let first = std::thread::spawn(move || run_init(&first_port, &first_dir, |_| Ok(())));
    let second_port = port.clone();
    let second_dir = runtime_dir;
    let second = std::thread::spawn(move || run_init(&second_port, &second_dir, |_| Ok(())));
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ProducerError::KeyStore))
            .count(),
        1
    );
    assert_eq!(port.0.lock().unwrap().len(), KeySlot::ALL.len());
}

#[test]
fn rollback_preserves_slot_changed_by_competing_writer() {
    let port = FakePort::default();
    port.values.borrow_mut().push((KeySlot::RootA, vec![9; 32]));
    assert_eq!(
        port.remove_if_value(KeySlot::RootA, KeySlot::RootA.account(), &[8; 32]),
        Err(ProducerError::KeyStore)
    );
    assert_eq!(
        port.values.borrow().as_slice(),
        &[(KeySlot::RootA, vec![9; 32])]
    );
}

#[test]
fn rollback_rejects_a_different_item_identity() {
    let port = FakePort::default();
    port.values.borrow_mut().push((KeySlot::RootA, vec![8; 32]));
    assert_eq!(
        port.remove_if_value(KeySlot::RootA, "foreign-item", &[8; 32]),
        Err(ProducerError::KeyStore)
    );
    assert_eq!(port.values.borrow().len(), 1);
}

#[test]
fn secret_service_attributes_are_fixed_to_the_intended_slot() {
    let attributes = crate::linux_secret_service::slot_attributes(KeySlot::RootA);
    assert_eq!(
        attributes.get("service"),
        Some(&crate::linux_secret_service::SERVICE)
    );
    assert_eq!(attributes.get("username"), Some(&"root-a"));
    assert_eq!(attributes.get("target"), Some(&"default"));
    assert_eq!(attributes.get("application"), Some(&"rust-keyring"));
}

#[test]
fn lock_rejects_runtime_directory_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("runtime");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let ran = RefCell::new(false);
    assert_eq!(
        with_init_lock(&alias, || {
            *ran.borrow_mut() = true;
            Ok(())
        }),
        Err(ProducerError::KeyStore)
    );
    assert!(!ran.into_inner());
}

#[test]
fn lock_rejects_lock_file_symlink() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let victim = directory.path().join("victim");
    fs::write(&victim, b"unchanged").unwrap();
    let lock_path = directory
        .path()
        .join("runne-update-metadata-producer-init.lock");
    std::os::unix::fs::symlink(&victim, &lock_path).unwrap();
    assert_eq!(
        with_init_lock(directory.path(), || Ok(())),
        Err(ProducerError::KeyStore)
    );
    assert_eq!(fs::read(victim).unwrap(), b"unchanged");
}

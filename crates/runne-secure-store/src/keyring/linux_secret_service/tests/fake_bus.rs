//! Deterministic in-memory Secret Service bus for facade tests.
//!
//! The fake negotiates a REAL DH session against the production facade crypto
//! (same prime/generator/HKDF/AES), so read/write roundtrips exercise the
//! actual wire encryption. Every invoked (method, destination) pair lands in
//! the shared log handle tests retain before binding.

use std::collections::HashMap;

use super::super::dh_session::{
    WireSecret, decrypt_with_iv, derive_shared_key, encrypt_with_iv, public_key, random_iv,
};
use super::fake_support::{DEFAULT_COLLECTION, FakeItem, FakeSession, InvocationLog};
use crate::keyring::linux_secret_service::port::{
    PeerCredentials, SecretServiceBus, SsBusError, SsMutationOutcome, SsSearchOutcome,
};
use std::cell::RefCell;
use std::rc::Rc;

const OWNER: &str = ":1.42";

/// Operation-level fault injection (lock flip, readback corruption, delete
/// failure) for targeted fail-closed testing.
#[derive(Clone, Copy, Default)]
pub struct FakeBusFaults {
    pub lock_items_before_get: bool,
    pub corrupt_readback: bool,
    pub fail_delete_item: bool,
}

pub struct FakeSecretServiceBus {
    log: InvocationLog,
    pub name_owned: bool,
    pub owner_name: String,
    pub peer: PeerCredentials,
    pub peer_alive: bool,
    pub connect_fails: bool,
    pub faults: FakeBusFaults,
    server_private: [u8; 128],
    session: Option<FakeSession>,
    items: Vec<(String, FakeItem)>,
    next_item: usize,
}

impl FakeSecretServiceBus {
    pub fn new() -> Self {
        Self {
            log: Rc::new(RefCell::new(Vec::new())),
            name_owned: true,
            owner_name: OWNER.to_owned(),
            peer: PeerCredentials {
                pid: 933,
                uid: 1000,
            },
            peer_alive: true,
            connect_fails: false,
            faults: FakeBusFaults::default(),
            server_private: core::array::from_fn(|i: usize| {
                u8::try_from((i * 11 + 7) & 0xff).expect("masked to u8")
            }),
            session: None,
            items: Vec::new(),
            next_item: 1,
        }
    }

    pub fn log_handle(&self) -> InvocationLog {
        Rc::clone(&self.log)
    }

    pub fn add_item(&mut self, attributes: &[(&str, &str)], data: &[u8], locked: bool) -> String {
        let path = self.item_path();
        self.items.push((
            path.clone(),
            FakeItem {
                attributes: attributes
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                locked,
                data: data.to_vec(),
            },
        ));
        path
    }

    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    fn item_path(&mut self) -> String {
        let path = format!(
            "/org/freedesktop/secrets/collection/default/{:02}",
            self.next_item
        );
        self.next_item += 1;
        path
    }

    fn record(&self, method: &str, dest: &str) -> Result<(), SsBusError> {
        self.log
            .borrow_mut()
            .push((method.to_owned(), dest.to_owned()));
        if self.connect_fails {
            return Err(SsBusError::Transport);
        }
        Ok(())
    }

    fn decrypt_wire(&self, secret: &WireSecret) -> Result<Vec<u8>, SsBusError> {
        let session = self.session.as_ref().ok_or(SsBusError::Transport)?;
        if secret.session_path != session.path {
            return Err(SsBusError::Transport);
        }
        Ok(decrypt_with_iv(&secret.data, &session.key, &secret.iv)?.to_vec())
    }

    fn encrypt_wire(&self, data: &[u8]) -> Result<WireSecret, SsBusError> {
        let session = self.session.as_ref().ok_or(SsBusError::Transport)?;
        let iv = random_iv();
        let encrypted = encrypt_with_iv(data, &session.key, &iv);
        Ok(WireSecret {
            session_path: session.path.clone(),
            iv: iv.to_vec(),
            data: encrypted,
            mime: "text/plain".to_owned(),
        })
    }

    fn position(&self, item: &str) -> Result<usize, SsBusError> {
        self.items
            .iter()
            .position(|(path, _)| path == item)
            .ok_or(SsBusError::Transport)
    }
}

impl Default for FakeSecretServiceBus {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretServiceBus for FakeSecretServiceBus {
    fn name_owner(&mut self, well_known: &str) -> Result<Option<String>, SsBusError> {
        self.record("GetNameOwner", well_known)?;
        Ok(self.name_owned.then(|| self.owner_name.clone()))
    }

    fn peer_credentials(&mut self, name: &str) -> Result<PeerCredentials, SsBusError> {
        self.record("GetConnectionUnixProcessID", name)?;
        if !self.peer_alive || name != self.owner_name {
            return Err(SsBusError::Transport);
        }
        Ok(self.peer)
    }

    fn open_session(
        &mut self,
        dest: &str,
        algorithm: &str,
        client_public: Vec<u8>,
    ) -> Result<(Vec<u8>, String), SsBusError> {
        self.record("OpenSession", dest)?;
        assert_eq!(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
        let key = derive_shared_key(&self.server_private, &client_public)?;
        let path = format!("/org/freedesktop/secrets/session/s{}", self.next_item);
        self.session = Some(FakeSession {
            path: path.clone(),
            key,
        });
        Ok((public_key(&self.server_private), path))
    }

    fn read_alias(&mut self, dest: &str, alias: &str) -> Result<Option<String>, SsBusError> {
        self.record("ReadAlias", dest)?;
        Ok((alias == "default").then(|| DEFAULT_COLLECTION.to_owned()))
    }

    fn search_items(
        &mut self,
        dest: &str,
        attributes: &[(String, String)],
    ) -> Result<SsSearchOutcome, SsBusError> {
        self.record("SearchItems", dest)?;
        let wanted: HashMap<&str, &str> = attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let mut outcome = SsSearchOutcome::default();
        for (path, item) in &self.items {
            let matches = wanted
                .iter()
                .all(|(key, value)| item.attributes.iter().any(|(k, v)| k == key && v == value));
            if matches {
                if item.locked {
                    outcome.locked.push(path.clone());
                } else {
                    outcome.unlocked.push(path.clone());
                }
            }
        }
        Ok(outcome)
    }

    fn get_secret(
        &mut self,
        dest: &str,
        session_path: &str,
        item: &str,
    ) -> Result<WireSecret, SsBusError> {
        self.record("GetSecret", dest)?;
        if self.faults.lock_items_before_get {
            for (_, entry) in &mut self.items {
                entry.locked = true;
            }
            return Err(SsBusError::Transport);
        }
        let session = self.session.as_ref().ok_or(SsBusError::Transport)?;
        if session.path != session_path {
            return Err(SsBusError::Transport);
        }
        let index = self.position(item)?;
        if self.items[index].1.locked {
            return Err(SsBusError::Transport);
        }
        let mut data = self.items[index].1.data.clone();
        if self.faults.corrupt_readback && !data.is_empty() {
            data[0] ^= 0xff;
        }
        self.encrypt_wire(&data)
    }

    fn set_item_secret(
        &mut self,
        dest: &str,
        item: &str,
        secret: WireSecret,
    ) -> Result<SsMutationOutcome, SsBusError> {
        self.record("SetSecret", dest)?;
        let data = self.decrypt_wire(&secret)?;
        let index = self.position(item)?;
        self.items[index].1.data = data;
        Ok(SsMutationOutcome::Done)
    }

    fn create_item(
        &mut self,
        dest: &str,
        collection: &str,
        label: &str,
        attributes: &[(String, String)],
        secret: WireSecret,
        replace: bool,
    ) -> Result<(Option<String>, SsMutationOutcome), SsBusError> {
        self.record("CreateItem", dest)?;
        assert_eq!(collection, DEFAULT_COLLECTION);
        assert!(replace);
        assert!(!label.is_empty());
        let data = self.decrypt_wire(&secret)?;
        let search: Vec<(String, String)> = attributes
            .iter()
            .filter(|(key, _)| key != "application" && key != "target")
            .cloned()
            .collect();
        let existing = self.items.iter().position(|(_, item)| {
            search
                .iter()
                .all(|(k, v)| item.attributes.iter().any(|(ik, iv)| ik == k && iv == v))
        });
        if let Some(index) = existing {
            self.items[index].1.data = data;
            return Ok((Some(self.items[index].0.clone()), SsMutationOutcome::Done));
        }
        let path = self.item_path();
        self.items.push((
            path.clone(),
            FakeItem {
                attributes: attributes.to_vec(),
                locked: false,
                data,
            },
        ));
        Ok((Some(path), SsMutationOutcome::Done))
    }

    fn delete_item(&mut self, dest: &str, item: &str) -> Result<SsMutationOutcome, SsBusError> {
        self.record("Delete", dest)?;
        if self.faults.fail_delete_item {
            return Err(SsBusError::Transport);
        }
        self.items.retain(|(path, _)| path != item);
        Ok(SsMutationOutcome::Done)
    }
}

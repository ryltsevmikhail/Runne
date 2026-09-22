//! Keyring-compatible Secret Service item layout.
//!
//! Mirrors the exact attributes, label, and collection semantics of the locked
//! `keyring 3.6.3` dependency so facade-written items are indistinguishable
//! from combo-store items and both halves of the store address the same
//! objects (Observed: `keyring-3.6.3/src/secret_service.rs`).

pub const CONTENT_TYPE: &str = "text/plain";
const APPLICATION: &str = "rust-keyring";
const TARGET_DEFAULT: &str = "default";
const LABEL_KEYRING_VERSION: &str = "3.6.3";

/// Identity of one entry (service + account), matching `Entry::new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryIdentity {
    pub service: String,
    pub account: String,
}

impl EntryIdentity {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }
}

/// Full item attributes used at creation (keyring sets exactly these four).
pub fn item_attributes(identity: &EntryIdentity) -> Vec<(String, String)> {
    vec![
        ("service".to_owned(), identity.service.clone()),
        ("username".to_owned(), identity.account.clone()),
        ("target".to_owned(), TARGET_DEFAULT.to_owned()),
        ("application".to_owned(), APPLICATION.to_owned()),
    ]
}

/// Search attributes (keyring searches on target+service+username).
pub fn search_attributes(identity: &EntryIdentity) -> Vec<(String, String)> {
    vec![
        ("target".to_owned(), TARGET_DEFAULT.to_owned()),
        ("service".to_owned(), identity.service.clone()),
        ("username".to_owned(), identity.account.clone()),
    ]
}

/// Item label byte-compatible with keyring 3.6.3 creation.
pub fn label(identity: &EntryIdentity) -> String {
    format!(
        "{}@{}:{} (keyring v{})",
        identity.account, identity.service, TARGET_DEFAULT, LABEL_KEYRING_VERSION
    )
}

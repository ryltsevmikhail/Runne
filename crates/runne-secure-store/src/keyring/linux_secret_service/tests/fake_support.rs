//! Shared fixtures/log invariants for the fake Secret Service bus.

use std::cell::RefCell;
use std::rc::Rc;

/// Every (method, destination) pair invoked through the fake bus.
pub type InvocationLog = Rc<RefCell<Vec<(String, String)>>>;

/// The complete allowed method set of the facade surface. Prompt and Unlock
/// are absent by construction; any other observed method fails the test.
pub const ALLOWED_METHODS: [&str; 10] = [
    "GetNameOwner",
    "GetConnectionUnixProcessID",
    "GetConnectionUnixUser",
    "OpenSession",
    "ReadAlias",
    "SearchItems",
    "GetSecret",
    "SetSecret",
    "CreateItem",
    "Delete",
];

pub fn assert_only_allowed_and_bound(log: &InvocationLog, bound_owner: &str) {
    for (method, dest) in log.borrow().iter() {
        assert!(
            ALLOWED_METHODS.contains(&method.as_str()),
            "non-allowed method {method} invoked; Prompt/Unlock are not part of the surface"
        );
        if !matches!(method.as_str(), "GetNameOwner") {
            assert!(
                dest == bound_owner || dest == "org.freedesktop.DBus",
                "method {method} went to {dest} instead of bound {bound_owner}"
            );
        }
    }
}

pub fn count_calls(log: &InvocationLog, method: &str) -> usize {
    log.borrow()
        .iter()
        .filter(|(name, _)| name == method)
        .count()
}

pub const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";

pub struct FakeItem {
    pub attributes: Vec<(String, String)>,
    pub locked: bool,
    pub data: Vec<u8>,
}

pub struct FakeSession {
    pub path: String,
    pub key: [u8; 16],
}

use crate::keyring::linux_secret_service::owner::{ExecutableFacts, OwnerError, ProcessFacts};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct FakeProcessFacts {
    uid: u32,
    executables: HashMap<u32, PathBuf>,
    metadata: HashMap<PathBuf, ExecutableFacts>,
}

impl FakeProcessFacts {
    pub fn new() -> Self {
        let exe = PathBuf::from("/usr/bin/gnome-keyring-daemon");
        let mut executables = HashMap::new();
        executables.insert(933, exe.clone());
        let mut metadata = HashMap::new();
        metadata.insert(
            exe,
            ExecutableFacts {
                uid: 0,
                mode: 0o755,
            },
        );
        Self {
            uid: 1000,
            executables,
            metadata,
        }
    }

    pub fn with_peer(&mut self, pid: u32, exe: &str, uid: u32, mode: u32) {
        let path = PathBuf::from(exe);
        self.executables.insert(pid, path.clone());
        self.metadata.insert(path, ExecutableFacts { uid, mode });
    }
}

impl Default for FakeProcessFacts {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessFacts for FakeProcessFacts {
    fn effective_uid(&self) -> u32 {
        self.uid
    }

    fn executable_path(&self, pid: u32) -> Result<PathBuf, OwnerError> {
        self.executables
            .get(&pid)
            .cloned()
            .ok_or(OwnerError::Unreadable)
    }

    fn executable_metadata(&self, path: &std::path::Path) -> Result<ExecutableFacts, OwnerError> {
        self.metadata
            .get(path)
            .copied()
            .ok_or(OwnerError::Unreadable)
    }
}

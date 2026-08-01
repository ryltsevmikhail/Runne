//! Sole owner of the client `SQLite` schema and migrations.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_secure_store::{AnchorStatus, SecureStore, SecureStoreError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

include!("schema.rs");
include!("models.rs");
include!("backup.rs");
include!("replay_types.rs");
include!("replay_journal.rs");
include!("replay_state.rs");
include!("replay_validation.rs");
include!("replay_hash.rs");
include!("anchor.rs");

mod mutation;
mod open;
mod projects;
mod replay_access;
mod replay_apply;
mod replay_confirm;

#[cfg(test)]
mod tests;

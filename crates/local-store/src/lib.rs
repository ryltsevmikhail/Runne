//! Sole owner of the client `SQLite` schema and migrations.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gocode_secure_store::SecureStoreError;
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
include!("security_state.rs");
#[allow(clippy::doc_markdown, clippy::format_collect)]
mod security_commit;
#[allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::format_collect
)]
mod security_mutation;
#[allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::redundant_clone,
    clippy::format_collect
)]
mod security_open;
#[allow(clippy::redundant_pub_crate)]
mod security_recovery;
#[allow(clippy::redundant_pub_crate)]
mod security_schema_v6;

mod open;
mod projects;
mod recent_root_backup;
mod recent_root_backup_compare;
mod recent_root_backup_failpoint;
mod recent_root_backup_files;
mod recent_root_backup_identity;
mod recent_root_migration;
mod recent_root_pre_v4_backup;
mod recent_root_schema;
mod recent_root_schema_indices;
mod recent_root_schema_normalize;
mod recent_root_schema_tables;
mod recent_roots;
mod replay_access;
#[allow(clippy::missing_errors_doc)]
mod replay_anchored;
mod replay_apply;
mod replay_confirm;

pub use recent_roots::{RecentRoot, RecentRootError};

#[cfg(feature = "test-support")]
pub mod recent_root_backup_test_support {
    pub use crate::recent_root_backup_failpoint::{
        AFTER_FILE_DURABLE, AFTER_PRIVATE_CREATE, AFTER_PUBLISH, AFTER_PUBLISH_DURABLE,
        AFTER_SNAPSHOT, BEFORE_MIGRATION, INSIDE_MIGRATION, set_failpoint,
    };
}

#[cfg(test)]
mod tests;

//! Sole owner of the client `SQLite` schema and migrations.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_secure_store::SecureStoreError;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

include!("schema.rs");
include!("models.rs");
include!("backup.rs");
include!("replay_types.rs");
include!("replay_shadow_types.rs");
include!("replay_shadow_authenticated.rs");
include!("replay_journal.rs");
include!("replay_state.rs");
include!("replay_validation.rs");
include!("replay_hash.rs");
include!("anchor.rs");
include!("security_state.rs");
mod protected_draft;
pub use protected_draft::{ProtectedDraft, ProtectedDraftError, ProtectedDraftScope};
#[allow(clippy::doc_markdown, clippy::format_collect)]
mod security_commit;
#[allow(clippy::format_collect)]
mod security_install;
mod security_ledger_v7;
mod security_legacy_v7_recovery;
#[allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::format_collect
)]
#[allow(clippy::redundant_pub_crate)]
mod security_mutation;
mod security_mutation_parts;
mod security_mutation_payload;
mod security_mutation_prepare;
#[allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::redundant_clone,
    clippy::format_collect
)]
mod security_open;
mod security_open_admitted;
mod security_open_hash;
#[allow(
    clippy::redundant_pub_crate,
    clippy::type_complexity,
    clippy::needless_pass_by_value
)]
mod security_record;
mod security_record_validate;
#[allow(clippy::redundant_pub_crate)]
mod security_recovery;
mod security_recovery_read;
mod security_recovery_read_types;
#[allow(clippy::redundant_pub_crate)]
mod security_schema_v6;
mod security_schema_v7;
#[allow(clippy::redundant_pub_crate)]
mod security_schema_v8;
mod security_schema_v9;
mod security_state_receipt;
#[allow(clippy::redundant_pub_crate)]
mod security_state_root;
mod security_v6_migration;
mod security_v8_migration;
mod security_v8_payload_migration;

pub use security_ledger_v7::{
    ApprovalDecisionKind, ApprovalOutcomeState, CanonicalMutationOutcome, GenerationAssistant,
    GenerationFailureReason, GenerationTerminal, LedgerMessage, MessageRole,
    NormalizedMutationCommand,
};
pub use security_recovery_read_types::{
    MAX_MUTATION_RECOVERY_RECORDS, MutationReceiptV7, MutationRecoveryBatch,
    MutationRecoveryBinding, MutationRecoveryEvidence, MutationRecoveryLimit,
};

#[cfg(feature = "test-support")]
pub mod security_open_test_support;
#[cfg(feature = "test-support")]
mod security_open_test_support_v8;
#[cfg(feature = "test-support")]
pub mod security_v6_test_support;

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
#[allow(clippy::redundant_pub_crate)]
mod replay_shadow;
mod replay_shadow_accept;
mod replay_shadow_apply;
mod replay_shadow_digest;
#[cfg(test)]
mod replay_shadow_tests;

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

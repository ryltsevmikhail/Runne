use std::path::Path;
use std::sync::Mutex;

use gocode_provider::{
    DispatchAttemptId, PreparedProviderRecord as ContractPreparedProviderRecord, ProviderCallId,
    ProviderDispatchClaim as ContractProviderDispatchClaim, ProviderDispatchRepository,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderRepositoryState,
    ProviderStreamId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

include!("dispatch_store/types.rs");
include!("dispatch_store/store.rs");
include!("dispatch_store/repository.rs");
include!("dispatch_store/helpers.rs");

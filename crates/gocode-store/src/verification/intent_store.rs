use std::path::Path;
use std::sync::{Arc, Mutex};

use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::evaluation::IntentError;
use gocode_domain::verification::identity::*;
use gocode_domain::verification::intent::{ConsumptionIntent, DispatchEvidence, IntentState};
use rusqlite::{Connection, Error as SqliteError, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::schema;

/// SQLite-backed intent store with durable, conditional state transitions.
#[derive(Clone)]
pub struct SqliteIntentStore {
    conn: Arc<Mutex<schema::ManagedConnection>>,
}

include!("intent_store_parts/store_impl.rs");
include!("intent_store_parts/helpers.rs");

#[cfg(test)]
mod tests {
    include!("intent_store_parts/tests.rs");
}

use std::fmt;
use std::path::Path;

use runne_domain::id::EventLogLineageId;
use runne_store::schema::recovery_diagnosis::diagnose_managed_recovery;
use runne_store::schema::{
    ConnectionMode, ManagedConnection, SchemaOpenDiagnostic, publication_from_managed,
    read_authority_id, read_event_log_lineage_id, readiness_from_managed,
    reopen_managed_connection_validated,
};

use super::*;
use crate::error::{RuntimeStoreOpenRejection, RuntimeStoreOpenStage, RuntimeStoreRejection};

/// Opens the managed runtime store connection for `purpose`.
///
/// DP1 contract (`backlog/plans/10-DP1-TRUST-BEACHHEAD.md`, section 7): on an
/// admission/reopen/verify failure the daemon keeps the structured typed
/// cause ([`crate::error::RuntimeStoreOpenRejection`]) up to its own
/// boundary — never raw store error text, no database path. `rejection`
/// classifies the original failure; the `recovery_state` from
/// [`diagnose_managed_recovery`] is supplementary typed file detail and never
/// replaces the rejection.
pub(super) fn open_runtime_connection(
    db_path: &str,
    mode: ConnectionMode,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
    purpose: &str,
) -> Result<ManagedConnection, DaemonError> {
    let connection = reopen_managed_connection_validated(Path::new(db_path), mode, |connection| {
        validate_runtime_identity(connection, authority_id, lineage_id)
    })
    .map_err(|error| store_open_rejection(db_path, purpose, RuntimeStoreOpenStage::Open, &error))?;
    readiness_from_managed(&connection)
        .and_then(|_| publication_from_managed(&connection).map(|_| ()))
        .map_err(|error| {
            store_open_rejection(db_path, purpose, RuntimeStoreOpenStage::Verify, &error)
        })?;
    Ok(connection)
}

/// Builds the typed daemon-boundary rejection for one failed stage.
///
/// Ordering is deliberate: [`classify_store_rejection`] reads the ORIGINAL
/// store error first; only afterwards does [`diagnose_managed_recovery`] run.
/// The recovery state is supplementary file detail — do not "simplify" the
/// diagnosis back into the place of the rejection cause.
fn store_open_rejection(
    db_path: &str,
    purpose: &str,
    stage: RuntimeStoreOpenStage,
    error: &rusqlite::Error,
) -> DaemonError {
    let rejection = classify_store_rejection(error);
    DaemonError::StoreOpenRejection(RuntimeStoreOpenRejection {
        purpose: purpose.to_owned(),
        stage,
        rejection,
        recovery_state: diagnose_managed_recovery(Path::new(db_path)),
    })
}

/// Distinguishable marker for an authority/lineage rejection, carried through
/// the store's `ToSqlConversionFailure` payload channel — the same idiom
/// `diagnostic_error` in `runne-store/src/schema.rs` uses for
/// `SchemaOpenDiagnostic`.
#[derive(Debug)]
struct RuntimeIdentityMismatch;

impl fmt::Display for RuntimeIdentityMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("runtime identity mismatch")
    }
}

impl std::error::Error for RuntimeIdentityMismatch {}

fn validate_runtime_identity(
    connection: &rusqlite::Connection,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
) -> rusqlite::Result<()> {
    if read_authority_id(connection)? == Some(authority_id)
        && read_event_log_lineage_id(connection)? == Some(lineage_id)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            RuntimeIdentityMismatch,
        )))
    }
}

/// Classifies the ORIGINAL store failure into the closed daemon-boundary
/// cause. Typed payloads travel in `ToSqlConversionFailure` boxes: the
/// store's own `SchemaOpenDiagnostic` admission diagnostics and the daemon's
/// [`RuntimeIdentityMismatch`] marker. Anything else (e.g. startup-gate
/// failures raising `rusqlite::Error::InvalidQuery`) has no typed payload in
/// the current store contract and fails closed as `Unavailable`.
fn classify_store_rejection(error: &rusqlite::Error) -> RuntimeStoreRejection {
    let rusqlite::Error::ToSqlConversionFailure(payload) = error else {
        return RuntimeStoreRejection::Unavailable;
    };
    if let Some(diagnostic) = payload.downcast_ref::<SchemaOpenDiagnostic>() {
        return RuntimeStoreRejection::Admission(*diagnostic);
    }
    if payload.downcast_ref::<RuntimeIdentityMismatch>().is_some() {
        return RuntimeStoreRejection::IdentityMismatch;
    }
    RuntimeStoreRejection::Unavailable
}

#[cfg(all(test, unix))]
mod tests;

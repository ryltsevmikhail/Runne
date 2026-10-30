//! Test-only controller-created DB; no process, native GO or custody grant.
use crate::schema::{self, ConnectionMode, ManagedConnection, TestOriginalDatabaseAnchor};
use runne_domain::id::EventLogLineageId;
use rusqlite::{Connection, Error, Result, types::ValueRef};
use std::{path::{Path, PathBuf}, os::unix::fs::PermissionsExt};

// Data-only reference from an admitted C role; never a runtime authority token.
#[derive(Clone, Copy)]
pub(in super::super) struct ExistingDatabase<'a> {
    pub(in super::super) path: &'a Path,
    pub(in super::super) authority: [u8;16],
    pub(in super::super) lineage: EventLogLineageId,
}

pub(in super::super) struct ControllerDatabase<'root> {
    _root: &'root tempfile::TempDir,
    path: PathBuf,
    authority: [u8;16],
    lineage: EventLogLineageId,
    anchor: TestOriginalDatabaseAnchor,
}
impl<'root> ControllerDatabase<'root> {
    pub(in super::super) fn create(root: &'root tempfile::TempDir) -> Result<Self> {
        // Exclusive new directories under the C-owned fresh root. No reuse/retry.
        let runtime = root.path().join("controller-runtime");
        let daemon = runtime.join("daemon");
        for path in [&runtime, &daemon] {
            std::fs::create_dir(path).map_err(|_| Error::InvalidQuery)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| Error::InvalidQuery)?;
        }
        let path = daemon.join("store.sqlite");
        let writer = schema::open_managed_connection(&path, ConnectionMode::Writer)?;
        schema::apply_migrations(&writer)?;
        let authority = uuid::Uuid::now_v7().into_bytes();
        schema::ensure_authority_id(&writer, &authority)?;
        let lineage = schema::ensure_event_log_lineage_id(&writer)?;
        let reference = ExistingDatabase { path: &path, authority, lineage };
        reference.validate(&writer)?;
        let anchor = writer.retain_test_original_anchor()?;
        drop(writer); // No inherited live SQLite connection at future W spawn.
        anchor.verify()?;
        Ok(Self { _root: root, path, authority, lineage, anchor })
    }
    pub(in super::super) fn reference(&self) -> ExistingDatabase<'_> {
        ExistingDatabase { path: &self.path, authority: self.authority, lineage: self.lineage }
    }
    pub(in super::super) fn anchor(&self) -> &TestOriginalDatabaseAnchor {
        &self.anchor
    }
}

impl ExistingDatabase<'_> {
    fn validate(&self, connection: &Connection) -> Result<()> {
        runne_domain::id::validate_uuid_v7_bytes(&self.authority).map_err(|_| Error::InvalidQuery)?;
        runne_domain::id::validate_uuid_v7_bytes(self.lineage.as_bytes()).map_err(|_| Error::InvalidQuery)?;
        let mut statement = connection.prepare("SELECT id,authority_id FROM main._authority LIMIT 2")?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(Error::InvalidQuery)?;
        if !matches!(row.get_ref(0)?, ValueRef::Integer(1)) ||
            !matches!(row.get_ref(1)?, ValueRef::Blob(v) if v == self.authority.as_slice()) {
            return Err(Error::InvalidQuery);
        }
        if rows.next()?.is_some() { return Err(Error::InvalidQuery); }
        drop(rows); drop(statement);
        let expected = self.lineage.to_string();
        let mut statement = connection.prepare("SELECT value FROM main._daemon_info
            WHERE key='event_log_lineage_id' LIMIT 2")?;
        let mut rows = statement.query([])?;
        let row = rows.next()?.ok_or(Error::InvalidQuery)?;
        if !matches!(row.get_ref(0)?, ValueRef::Text(v) if v == expected.as_bytes()) {
            return Err(Error::InvalidQuery);
        }
        if rows.next()?.is_some() { return Err(Error::InvalidQuery); }
        let version: i64 = connection.query_row("SELECT MAX(version) FROM main.schema_version", [], |r| r.get(0))?;
        if version != schema::CURRENT_SCHEMA_VERSION { return Err(Error::InvalidQuery); }
        Ok(())
    }

    // Reopen only: no migration/ensure/new database or immutable fallback.
    pub(in super::super) fn open(&self) -> Result<(PathBuf, ManagedConnection, ManagedConnection)> {
        let writer = schema::reopen_managed_connection_validated(self.path,
            ConnectionMode::ValidatedReopen, |c| self.validate(c))?;
        let reader = schema::reopen_managed_connection_validated(self.path,
            ConnectionMode::Reader, |c| self.validate(c))?;
        if !reader.same_database_identity(&writer)? { return Err(Error::InvalidQuery); }
        self.validate(&writer)?; self.validate(&reader)?;
        Ok((self.path.to_path_buf(), writer, reader))
    }
}

#[cfg(test)]
#[path = "fixture_existing_database_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "fixture_existing_native_tests.rs"]
mod native_tests;

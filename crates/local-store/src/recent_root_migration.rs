use std::collections::HashSet;
use std::path::Path;

use super::recent_root_backup::validate_source;
use super::recent_root_backup::{VerifiedPreV5Backup, attach_verified_backup};
use super::recent_root_backup_compare::v4_tables_equal;
use super::recent_root_backup_failpoint::{BEFORE_MIGRATION, INSIDE_MIGRATION, hit};
use super::recent_roots::{valid_display_name, valid_native_metadata};
use super::{LocalStore, StoreOpenError, TransactionBehavior, params};

impl LocalStore {
    pub(super) fn migrate_v4_recent_roots(
        &mut self,
        backup: VerifiedPreV5Backup,
    ) -> Result<(), StoreOpenError> {
        attach_verified_backup(&self.connection, backup)?;
        hit(BEFORE_MIGRATION)?;
        let result = self.migrate_attached_v4_recent_roots();
        self.connection
            .execute_batch("DETACH DATABASE pre_v5_backup")
            .map_err(|_| StoreOpenError::PreV5BackupRecoveryRequired)?;
        result
    }

    fn migrate_attached_v4_recent_roots(&mut self) -> Result<(), StoreOpenError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        hit(INSIDE_MIGRATION)?;
        validate_source(&transaction)?;
        if !v4_tables_equal(&transaction).map_err(|_| StoreOpenError::PreV5BackupSourceMismatch)? {
            return Err(StoreOpenError::PreV5BackupSourceMismatch);
        }
        let legacy = read_legacy_roots(&transaction)?;
        let legacy_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
        if legacy_count
            != i64::try_from(legacy.len())
                .map_err(|_| StoreOpenError::RecentRootMigrationCorrupt)?
        {
            return Err(StoreOpenError::RecentRootMigrationCorrupt);
        }
        transaction.execute_batch(
            "
            CREATE TABLE recent_roots (
                project_id TEXT,
                workspace_id TEXT,
                display_name TEXT NOT NULL,
                last_opened_at INTEGER NOT NULL CHECK (last_opened_at >= 0 AND last_opened_at <= 9007199254740991),
                root_state TEXT NOT NULL CHECK (root_state IN ('ready', 'migration_required')),
                native_root_metadata TEXT,
                legacy_project_id INTEGER UNIQUE,
                CHECK (
                    (root_state = 'ready'
                        AND project_id IS NOT NULL
                        AND workspace_id IS NOT NULL
                        AND native_root_metadata IS NOT NULL
                        AND legacy_project_id IS NULL)
                    OR
                    (root_state = 'migration_required'
                        AND project_id IS NULL
                        AND workspace_id IS NULL
                        AND legacy_project_id IS NOT NULL
                        AND native_root_metadata IS NOT NULL)
                ),
                UNIQUE (workspace_id),
                UNIQUE (native_root_metadata)
            ) STRICT;
            ",
        )?;
        for root in &legacy {
            transaction.execute(
                "
                INSERT INTO recent_roots (
                    project_id, workspace_id, display_name, last_opened_at,
                    root_state, native_root_metadata, legacy_project_id
                ) VALUES (NULL, NULL, ?1, ?2, 'migration_required', ?3, ?4)
                ",
                params![
                    root.display_name,
                    root.last_opened_at,
                    root.native_metadata,
                    root.id
                ],
            )?;
        }
        transaction.execute_batch(
            "
            DROP TABLE projects;
            UPDATE meta SET schema_version = 5 WHERE singleton = 1;
            PRAGMA user_version = 5;
            ",
        )?;
        let migrated_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM recent_roots", [], |row| row.get(0))?;
        let meta: (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(MIN(schema_version), 0) FROM meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if migrated_count != legacy_count || meta != (1, 5) {
            return Err(StoreOpenError::RecentRootMigrationCorrupt);
        }
        super::recent_root_schema::validate_v5_schema(&transaction)?;
        transaction.commit()?;
        Ok(())
    }
}

struct LegacyRecentRoot {
    id: i64,
    display_name: String,
    last_opened_at: i64,
    native_metadata: String,
}

fn read_legacy_roots(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<Vec<LegacyRecentRoot>, StoreOpenError> {
    let mut statement = transaction
        .prepare("SELECT id, name, path, last_opened_at FROM projects ORDER BY id ASC")?;
    let mut rows = statement.query([])?;
    let mut legacy = Vec::new();
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row
            .get(0)
            .map_err(|_| StoreOpenError::RecentRootMigrationCorrupt)?;
        let display_name: String = row
            .get(1)
            .map_err(|_| StoreOpenError::RecentRootMigrationCorrupt)?;
        let native_metadata: String = row
            .get(2)
            .map_err(|_| StoreOpenError::RecentRootMigrationCorrupt)?;
        let last_opened_at: i64 = row
            .get(3)
            .map_err(|_| StoreOpenError::RecentRootMigrationCorrupt)?;
        if id <= 0
            || !(0..=9_007_199_254_740_991).contains(&last_opened_at)
            || !ids.insert(id)
            || !paths.insert(native_metadata.clone())
            || !valid_display_name(&display_name)
            || !valid_native_metadata(&native_metadata)
            || !Path::new(&native_metadata).is_absolute()
        {
            return Err(StoreOpenError::RecentRootMigrationCorrupt);
        }
        legacy.push(LegacyRecentRoot {
            id,
            display_name,
            last_opened_at,
            native_metadata,
        });
    }
    Ok(legacy)
}

use std::path::Path;

use rusqlite::Connection;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuthorityRow {
    pub(super) capability_expires_at: i64,
    pub(super) approval_expires_at: i64,
    pub(super) state_revision: i64,
    pub(super) active: i64,
}

pub(super) fn authority_row(path: &Path) -> AuthorityRow {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT capability_expires_at, approval_expires_at, state_revision, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok(AuthorityRow {
                    capability_expires_at: row.get(0)?,
                    approval_expires_at: row.get(1)?,
                    state_revision: row.get(2)?,
                    active: row.get(3)?,
                })
            },
        )
        .unwrap()
}

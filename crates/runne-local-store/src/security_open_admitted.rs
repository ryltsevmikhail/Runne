use crate::{Connection, LocalStore, Path, SecurityStateError};
use runne_sqlite_native_identity::{
    DatabaseFileIdentity, opened_database_identity, path_database_identity,
};

impl LocalStore {
    pub(crate) fn open_admitted(
        path: &Path,
        expected: Option<DatabaseFileIdentity>,
    ) -> Result<Self, SecurityStateError> {
        #[cfg(feature = "test-support")]
        crate::security_open_test_support::before_admitted_open();
        let opened = Connection::open(path);
        #[cfg(feature = "test-support")]
        crate::security_open_test_support::after_admitted_open();
        let connection = opened?;
        if expected.is_some_and(|identity| {
            path_database_identity(path).ok() != Some(identity)
                || opened_database_identity(&connection).ok() != Some(identity)
        }) {
            return Err(SecurityStateError::AdmissionFailed);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        Ok(Self {
            connection,
            security: None,
        })
    }
}

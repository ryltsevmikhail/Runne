use std::sync::Arc;

#[cfg(feature = "desktop-protected")]
use crate::application::root_handle_admission::PermissionStartupBundle;
use crate::error::DaemonError;
use runne_application::ports::{CommitError, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
#[cfg(feature = "desktop-protected")]
use runne_store::ProjectTrustStore;
use runne_store::schema::ManagedConnection;
use runne_store::store::StoreTransaction;

#[cfg(feature = "desktop-protected")]
pub(super) fn prepare(
    config: &crate::application::ConfigurationSnapshot,
) -> Result<PermissionStartupBundle, DaemonError> {
    PermissionStartupBundle::prepare(
        std::path::Path::new(&config.db_path),
        std::path::Path::new(&config.replay_integrity_key_path),
    )
}

#[cfg(feature = "desktop-protected")]
pub(super) fn open(
    db_path: &str,
    writer: ManagedConnection,
    reader: ManagedConnection,
    authority: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    permission_startup: &PermissionStartupBundle,
    trust_store: Option<Arc<ProjectTrustStore>>,
) -> Result<StoreTransaction, DaemonError> {
    permission_startup
        .open_store(
            db_path,
            writer,
            reader,
            authority,
            prohibited_content,
            trust_store,
        )
        .map_err(store_open_error)
}

#[cfg(not(feature = "desktop-protected"))]
pub(super) fn open(
    db_path: &str,
    writer: ManagedConnection,
    reader: ManagedConnection,
    authority: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> Result<StoreTransaction, DaemonError> {
    StoreTransaction::open_with_connections(db_path, writer, reader, authority, prohibited_content)
        .map_err(store_open_error)
}

fn store_open_error(error: CommitError) -> DaemonError {
    DaemonError::Bootstrap(format!("open runtime store: {error:?}"))
}

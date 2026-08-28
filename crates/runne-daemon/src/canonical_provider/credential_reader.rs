use std::sync::Arc;

use runne_secure_store::{
    NativeProviderCredentialReaders, ProviderCredentialAccessPolicy,
    ProviderCredentialDispatchMaterializer, ProviderCredentialReadback,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use crate::error::DaemonError;

pub(super) struct ComposedCredentialReaders {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) readback: Arc<dyn ProviderCredentialReadback>,
    pub(super) dispatch: Arc<dyn ProviderCredentialDispatchMaterializer>,
}

pub(super) fn compose(
    connection: ManagedConnection,
    access: ProviderCredentialAccessPolicy,
) -> Result<ComposedCredentialReaders, DaemonError> {
    let (lifecycle_authority, readback, dispatch, _) =
        NativeProviderCredentialReaders::new(access).into_parts();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authority(
        connection,
        lifecycle_authority,
    )
    .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
    Ok(ComposedCredentialReaders {
        store: Arc::new(store),
        readback,
        dispatch,
    })
}

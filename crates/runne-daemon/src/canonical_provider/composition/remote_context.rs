use super::*;

pub(super) fn compose(
    keyring: &Arc<dyn ProviderJournalKeyring>,
    execution_store: &Arc<SqliteProviderExecutionStore>,
) -> (
    Arc<dyn runne_provider::ProviderRecoveryDispatchContextProvider>,
    Arc<dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
) {
    let context = runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(keyring),
        Arc::clone(execution_store),
    );
    let facts = runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(keyring),
        Arc::clone(execution_store),
    );
    (Arc::new(context), Arc::new(facts))
}

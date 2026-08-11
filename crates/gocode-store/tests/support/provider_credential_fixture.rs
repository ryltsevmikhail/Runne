use gocode_provider::{
    CredentialLease, CredentialVersionRef, PrepareCredentialVersion,
    ProviderCredentialVersionStore, ProviderId,
};
use gocode_store::provider::SqliteProviderCredentialLifecycleStore;

pub fn credential(
    database: &super::validated_reopen::ProviderTestDatabase,
    provider: &str,
    owner: [u8; 16],
    fence: u64,
    now: i64,
) -> SqliteProviderCredentialLifecycleStore {
    let store =
        SqliteProviderCredentialLifecycleStore::open_connection_at(database.connection(), now)
            .unwrap();
    let provider = ProviderId::new(provider).unwrap();
    let reference = CredentialVersionRef::new(provider, 1).unwrap();
    store
        .create_prepared(PrepareCredentialVersion::new(reference.clone()))
        .unwrap();
    store
        .activate(CredentialLease::new(reference, owner, i64::MAX, fence).unwrap())
        .unwrap();
    store
}

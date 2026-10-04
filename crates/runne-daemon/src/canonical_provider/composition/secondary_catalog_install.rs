use crate::canonical_provider::VerifiedSecondaryCatalog;

fn install_secondary_profile_catalog(
    store: &SqliteProviderExecutionStore,
    launch: &ProviderRuntimeLaunchCapability,
    catalog: Option<VerifiedSecondaryCatalog>,
    db_path: &str,
    authority_id: [u8; 16],
) -> Result<Option<runne_store::provider::ProviderSecondaryProfileGrant>, DaemonError> {
    let Some(catalog) = catalog else {
        return Ok(None);
    };
    if catalog.db_path() != db_path
        || catalog.authority_id() != authority_id
        || catalog.digest() == [0; 32]
    {
        return Err(DaemonError::Bootstrap(
            "verified secondary provider catalog binding mismatch".into(),
        ));
    }
    store
        .install_secondary_profile_grant_if_active(launch, catalog.spec().clone())
        .map_err(|_| DaemonError::Bootstrap("secondary provider catalog grant unavailable".into()))
}

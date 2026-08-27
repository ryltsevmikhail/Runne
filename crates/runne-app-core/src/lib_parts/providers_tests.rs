#[test]
fn provider_statuses_require_an_authenticated_owner_projection() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");

    assert!(matches!(
        core.provider_statuses().expect_err("unconfigured owner"),
        AppCoreError::RuntimeUnavailable
    ));
}

#[test]
fn app_core_has_no_legacy_provider_credential_mutation_ingress() {
    const SOURCE: &str = include_str!("providers.rs");
    for prohibited in [
        "pair_provider_credential",
        "revoke_provider_credential",
        "PairProviderCredentialRequest",
        "RevokeProviderCredentialRequest",
        "ProviderCredentialMutationAckDto",
    ] {
        assert!(
            !SOURCE.contains(prohibited),
            "legacy provider credential ingress remains reachable: {prohibited}"
        );
    }
}

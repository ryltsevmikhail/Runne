use super::*;

#[test]
fn legacy_import_readback_binds_the_retained_source_revision() {
    let first = VersionStoreReadback::new(ConfiguredVersionStore([7; 16]), access())
        .readback_exact_version(ExactVersionReadback::new(legacy_import_command(1, 1)).unwrap())
        .unwrap();
    let second = VersionStoreReadback::new(ConfiguredVersionStore([8; 16]), access())
        .readback_exact_version(ExactVersionReadback::new(legacy_import_command(1, 1)).unwrap())
        .unwrap();

    assert!(first.present());
    assert!(second.present());
    assert_ne!(first.binding(), second.binding());
    let service = ExactVersionReadback::new(legacy_import_command(1, 1))
        .unwrap()
        .observe_service_metadata(
            true,
            Some(crate::ProviderCredentialSourceRevision::new([7; 16]).unwrap()),
        )
        .unwrap();
    assert_eq!(service.binding(), first.binding());
    assert_ne!(service.binding(), second.binding());
    assert_eq!(
        ExactVersionReadback::new(legacy_import_command(1, 1))
            .unwrap()
            .observe_service_metadata(true, None),
        Err(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)
    );
}

#[test]
fn service_revision_cannot_convert_pair_or_absence_into_import_success() {
    let revision = crate::ProviderCredentialSourceRevision::new([7; 16]).unwrap();
    assert_eq!(
        ExactVersionReadback::new(command(1, 1))
            .unwrap()
            .observe_service_metadata(true, Some(revision)),
        Err(SecureStoreError::CredentialAccessDenied)
    );
    assert_eq!(
        ExactVersionReadback::new(legacy_import_command(1, 1))
            .unwrap()
            .observe_service_metadata(false, Some(revision)),
        Err(SecureStoreError::CredentialAccessDenied)
    );
}

pub(super) fn setup() -> (
    SqliteProviderCredentialLifecycleStore,
    CredentialEnrollmentMeasurementAuthority,
) {
    setup_expiry(200)
}

fn setup_expiry(
    expiry: u64,
) -> (
    SqliteProviderCredentialLifecycleStore,
    CredentialEnrollmentMeasurementAuthority,
) {
    let path = tempfile::tempdir().unwrap().keep().join("qualified.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (issuer, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_authorities_and_now(
        &path,
        lifecycle,
        issuer,
        Arc::new(|| 100),
    )
    .unwrap();
    store
        .begin(super::online_test_support::begin_with_operation(
            1,
            1,
            "qualified",
            2,
            expiry,
        ))
        .unwrap();
    store
        .attach_process(AttachCredentialProcess::new(operation(1), digest(4)).unwrap())
        .unwrap();
    (store, measurements)
}

pub(super) fn admission(
    measurements: &CredentialEnrollmentMeasurementAuthority,
) -> MeasuredQualificationAdmission {
    admission_at(measurements, 100)
}

fn admission_at(
    measurements: &CredentialEnrollmentMeasurementAuthority,
    verified: u64,
) -> MeasuredQualificationAdmission {
    admission_bound(measurements, verified, operation(1), [1, 2, 3, 4])
}

fn admission_bound(
    measurements: &CredentialEnrollmentMeasurementAuthority,
    verified: u64,
    operation: runne_provider::CredentialOperationId,
    ids: [u8; 4],
) -> MeasuredQualificationAdmission {
    measurements
        .measure_qualification_admission(
            super::qualification_fixture::facts(ids, 90, 180, verified),
            QualificationSessionBinding {
                protected_session: digest(10),
                continuation: digest(4),
                runtime_authority: [11; 16],
                database_generation: 1,
                launch_generation: 2,
                supervisor_generation: 3,
            },
            operation,
            verified,
        )
        .unwrap()
}

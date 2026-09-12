pub(super) fn preflight_resume_first_activation(
    config: &ConfigurationSnapshot,
    pending: &PendingFirstActivationV1,
    enrollment_capability: Option<&super::launch::VerifiedProtectedEnrollmentCapability>,
) -> Result<(), LaunchAuthorityError> {
    let profile = expected_profile(enrollment_capability)?;
    let db_path = Path::new(&config.db_path);
    match schema::open_existing_read_only(db_path) {
        Ok(connection) => {
            validate_resume_first_activation_connection(config, &connection, pending, &profile)
        }
        Err(_) => schema::with_protected_recovery_read_only_admission(db_path, |connection| {
            validate_resume_first_activation_connection(config, connection, pending, &profile)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch),
    }
}

pub(super) fn validate_resume_first_activation_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    pending: &PendingFirstActivationV1,
    expected_profile: &ProtectedRuntimeProfileV1,
) -> Result<(), LaunchAuthorityError> {
    if pending.profile() != expected_profile {
        return Err(LaunchAuthorityError::ProfileHashMismatch);
    }
    let lineage = uuid::Uuid::from_bytes(*pending.stable().lineage_id())
        .to_string()
        .parse()
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
    match schema::preflight_first_activation_resume(
        connection,
        pending.stable().authority_id(),
        lineage,
        pending.preparation_id(),
    )
    .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?
    {
        schema::FirstActivationResumeState::Prepared => validate_existing_connection(
            config,
            connection,
            pending.stable(),
            Some(pending.preparation_id()),
            expected_profile,
        ),
        schema::FirstActivationResumeState::RecoverablePrepared => {
            preflight_recoverable_first_activation_sidecars(config, pending.stable().authority_id())
                .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)
        }
        schema::FirstActivationResumeState::RecoverablePartial => {
            let replay_key = Path::new(&config.replay_integrity_key_path);
            let local_authority = replay_key.with_file_name("local-session-authority-id");
            if replay_key.exists() || local_authority.exists() {
                return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
            }
            Ok(())
        }
    }
}

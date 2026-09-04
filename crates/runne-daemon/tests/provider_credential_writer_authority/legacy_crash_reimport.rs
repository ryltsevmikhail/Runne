use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialProviderV2,
};
use runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin;
use zeroize::Zeroizing;

pub(super) async fn assert_fresh_migrate_is_rejected(
    context: &super::support::InnerContext,
) -> Result<String, &'static str> {
    let (mut supervisor, _) = super::legacy_crash::enter_v3(context).await?;
    let secret = Zeroizing::new(super::audit::secret_canary(context.root()));
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::MigrateLegacy,
        ProviderCredentialProviderV2::OpenAi,
        1,
        &command_id,
        format!("crash-reimport-{command_id}"),
        "crash-reimport-intent",
    )
    .map_err(|_| "reimport-command")?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(
        command,
        super::audit::ticket_canary(secret.as_slice()),
    )
    .map_err(|_| "reimport-native-begin")?;
    let admission = supervisor.begin_protected_credential_enrollment(begin);
    let rejected = admission.is_err();
    drop(admission);
    supervisor.stop().map_err(|_| "reimport-stop")?;
    if !rejected {
        return Err("reimport-admitted-after-consumption");
    }
    assert_operation_counts(context)?;
    Ok(format!("fresh-migrate-legacy-rejected:{command_id}"))
}

fn assert_operation_counts(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (imports, cleanups): (i64, i64) = super::legacy_observations::database(context)?
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_credential_operations WHERE action='MIGRATE_LEGACY'),
                (SELECT COUNT(*) FROM provider_credential_operations WHERE action='LEGACY_SOURCE_CLEANUP')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "reimport-operation-count")?;
    (imports == 1 && cleanups == 1)
        .then_some(())
        .ok_or("reimport-operation-count")
}

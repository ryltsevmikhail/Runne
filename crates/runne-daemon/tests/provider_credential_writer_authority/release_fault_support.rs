use std::process::Command;
use std::time::Duration;

use runne_api::{BeginProviderCredentialEnrollment, ProviderReadinessStatusV1};
use runne_platform_desktop::{
    NativeProtectedCredentialEnrollmentBegin, ProtectedBundledRuntimeSupervisor,
};

pub(super) fn require_incomplete(
    context: &super::support::InnerContext,
    expected: &str,
) -> Result<(), &'static str> {
    super::native_item::assert_absent(context.root())?;
    assert_operation_state(context, expected)
}

pub(super) fn assert_operation_state(
    context: &super::support::InnerContext,
    expected: &str,
) -> Result<(), &'static str> {
    let database = context.runtime_root().join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "sqlite-open")?;
    let state: String = connection
        .query_row(
            "SELECT state FROM provider_credential_operations",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-state")?;
    (state == expected).then_some(()).ok_or("truthful-state")
}

pub(super) fn require_not_completed(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let database = context.runtime_root().join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "sqlite-open")?;
    let completed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_operations WHERE state = 'COMPLETED'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-state")?;
    (completed == 0)
        .then_some(())
        .ok_or("unexpected-completion")
}

pub(super) async fn restart_with(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    context: &super::support::InnerContext,
    command: BeginProviderCredentialEnrollment,
    expected: ProviderReadinessStatusV1,
) -> Result<(), &'static str> {
    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("restart-local-admission")?;
    supervisor.start().map_err(|_| "restart-runned")?;
    let client = super::support::connect(supervisor, "fault-restart").await?;
    if super::support::require_selected(&client, expected).is_err() {
        super::support::require_selected(
            &client,
            ProviderReadinessStatusV1::SecureStoreUnavailable,
        )?;
    }
    supervisor
        .record_client_ready(&client)
        .map_err(|_| "restart-control-ready")?;
    drop(client);
    let confirmed = supervisor
        .confirm_installed_native_enrollment(prepared)
        .map_err(|_| "restart-local-confirmation")?;
    supervisor
        .begin_credential_enrollment_transition(&confirmed)
        .map_err(|_| "restart-v3-transition")?;
    let v3 = super::support::connect(supervisor, "restart-v3").await?;
    supervisor
        .record_client_ready(&v3)
        .map_err(|_| "restart-v3-ready")?;
    drop(v3);
    super::support::register_credential_service_session(supervisor, &confirmed).await?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(command, [79; 32])
        .map_err(|_| "restart-native-begin")?;
    let recovered = supervisor
        .begin_protected_credential_enrollment(begin)
        .map_err(|_| "restart-recovery-begin")?;
    if !recovered.terminal() {
        return Err("restart-recovery-nonterminal");
    }
    let renewed = supervisor
        .renew_profile()
        .map_err(|_| "restart-renew")?
        .connect(Duration::from_secs(10))
        .await
        .map_err(|_| "restart-renew-connect")?;
    super::support::require_selected(&renewed, expected)?;
    supervisor
        .record_client_ready(&renewed)
        .map_err(|_| "restart-ready")?;
    drop(renewed);
    supervisor.stop().map(|_| ()).map_err(|_| "restart-stop")
}

pub(super) fn assert_no_owned_children(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "state=,command="])
        .output()
        .map_err(|_| "ps-command")?;
    if !output.status.success() {
        return Err("ps-status");
    }
    let writer = context.writer();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let _state = fields.next();
        let executable = fields.next().map(std::path::Path::new);
        if executable == Some(writer.as_path()) || executable == Some(context.daemon()) {
            return Err("owned-child-survived");
        }
    }
    Ok(())
}

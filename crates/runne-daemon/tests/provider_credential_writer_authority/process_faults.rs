use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2, ProviderReadinessStatusV1,
};
use runne_platform_desktop::{
    CredentialWriterHandoffMode, NativeProtectedCredentialEnrollmentBegin,
};

pub(super) fn run() {
    super::harness::dispatch_scenarios(
        "wrong_replaced_and_stale_writer_attempts_have_zero_native_effect",
        &["wrong", "replaced", "stale"],
        inner,
    );
}

fn inner(context: &super::support::InnerContext, scenario: &str) -> Result<(), &'static str> {
    match scenario {
        "wrong" => wrong_writer(context),
        "replaced" => replaced_after_measurement(context),
        "stale" => stale_after_daemon_restart(context),
        _ => Err("unknown-process-fault"),
    }
}

fn wrong_writer(context: &super::support::InnerContext) -> Result<(), &'static str> {
    replace_writer(context, context.daemon())?;
    if runne_platform_desktop::prepare_local_native_enrollment(context.profile()).is_some() {
        return Err("wrong-writer-admitted");
    }
    super::native_item::assert_absent(context.root())
}

fn replaced_after_measurement(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("local-admission")?;
    let writer = context.writer();
    fs::set_permissions(&writer, fs::Permissions::from_mode(0o700))
        .map_err(|_| "writer-mutable")?;
    OpenOptions::new()
        .append(true)
        .open(&writer)
        .and_then(|mut file| file.write_all(b"slice-e-replaced"))
        .map_err(|_| "writer-replacement")?;
    fs::set_permissions(&writer, fs::Permissions::from_mode(0o500)).map_err(|_| "writer-reseal")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "tokio-runtime")?;
    runtime.block_on(async {
        let mut supervisor = context.supervisor()?;
        supervisor.start().map_err(|_| "runned-start")?;
        let client = super::support::connect(&mut supervisor, "replaced").await?;
        super::support::require_selected(&client, ProviderReadinessStatusV1::CredentialMissing)?;
        supervisor
            .record_client_ready(&client)
            .map_err(|_| "runned-ready")?;
        drop(client);
        if supervisor
            .confirm_installed_native_enrollment(prepared)
            .is_ok()
        {
            return Err("replaced-writer-confirmed");
        }
        supervisor.stop().map_err(|_| "runned-stop")?;
        super::native_item::assert_absent(context.root())
    })
}

fn stale_after_daemon_restart(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "tokio-runtime")?;
    runtime.block_on(async {
        let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
            .ok_or("local-admission")?;
        let mut supervisor = context.supervisor()?;
        supervisor.start().map_err(|_| "initial-runned-start")?;
        let initial = super::support::connect(&mut supervisor, "stale-initial").await?;
        super::support::require_selected(&initial, ProviderReadinessStatusV1::CredentialMissing)?;
        supervisor
            .record_client_ready(&initial)
            .map_err(|_| "initial-ready")?;
        drop(initial);
        let confirmed = supervisor
            .confirm_installed_native_enrollment(prepared)
            .map_err(|_| "local-confirmation")?;
        supervisor
            .begin_credential_enrollment_transition(&confirmed)
            .map_err(|_| "v3-transition")?;
        let v3 = super::support::connect(&mut supervisor, "stale-v3").await?;
        supervisor
            .record_client_ready(&v3)
            .map_err(|_| "v3-ready")?;
        drop(v3);

        let mut enrollment = supervisor
            .begin_protected_credential_enrollment(begin_command()?)
            .map_err(|_| "protected-begin")?;
        if enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Prepared {
            return Err("prepared-state");
        }
        let mut handoff = supervisor
            .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::Pair)
            .map_err(|_| "writer-handoff")?;
        supervisor
            .receive_credential_secret_relay(&mut enrollment)
            .map_err(|_| "secret-relay")?;
        let relay = enrollment.take_relay().ok_or("relay-take")?;
        let sealer = handoff.take_pair_secret_relay().ok_or("pair-relay")?;

        let _ = supervisor.abort_protected_credential_enrollment();
        let _ = supervisor.stop();
        let secret = zeroize::Zeroizing::new(super::audit::secret_canary(context.root()));
        if sealer.seal_and_write(&relay, secret).is_ok() {
            return Err("stale-fd3-accepted");
        }
        handoff
            .reap_exact_writer_bounded(Duration::from_secs(10))
            .map_err(|_| "writer-reap")?;
        super::native_item::assert_absent(context.root())?;
        assert_not_completed(context.runtime_root())?;

        let mut restarted = context.supervisor()?;
        restarted.start().map_err(|_| "restart-runned")?;
        let client = super::support::connect(&mut restarted, "stale-restart").await?;
        super::support::require_selected(&client, ProviderReadinessStatusV1::CredentialMissing)?;
        restarted
            .record_client_ready(&client)
            .map_err(|_| "restart-ready")?;
        drop(client);
        restarted.stop().map_err(|_| "restart-stop")?;
        Ok(())
    })
}

fn begin_command() -> Result<NativeProtectedCredentialEnrollmentBegin, &'static str> {
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        &command_id,
        format!("slice-e-stale-{command_id}"),
        "slice-e-stale-intent",
    )
    .map_err(|_| "begin-command")?;
    NativeProtectedCredentialEnrollmentBegin::new(command, [73; 32]).map_err(|_| "native-begin")
}

fn replace_writer(
    context: &super::support::InnerContext,
    replacement: &std::path::Path,
) -> Result<(), &'static str> {
    let writer = context.writer();
    fs::set_permissions(&writer, fs::Permissions::from_mode(0o700))
        .map_err(|_| "writer-mutable")?;
    fs::copy(replacement, &writer).map_err(|_| "wrong-writer-copy")?;
    fs::set_permissions(writer, fs::Permissions::from_mode(0o500)).map_err(|_| "writer-reseal")
}

fn assert_not_completed(runtime: &std::path::Path) -> Result<(), &'static str> {
    let database = runtime.join("runne-daemon/event-log.db");
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "sqlite-open")?;
    let completed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_operations WHERE state='COMPLETED'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-state")?;
    (completed == 0).then_some(()).ok_or("completed-state")
}

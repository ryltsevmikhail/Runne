use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2, ProviderReadinessStatusV1,
};
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, CredentialWriterHandoffMode,
    NativeProtectedCredentialEnrollmentBegin,
};
use zeroize::Zeroizing;

const SELECTOR: &str = "revoke_partial_native_delete_recovers_without_restoring_old_versions";
const SCENARIO: &str = "revoke-partial-delete";
const MARKER: &str = "retired-version-delete.marker";
const RELEASE: &str = "retired-version-delete.release";

pub(super) fn run() {
    super::harness::dispatch_scenarios(SELECTOR, &[SCENARIO], |context, _| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "revocation-tokio")?;
        runtime.block_on(run_scenario(context))
    });
}

async fn run_scenario(context: &super::support::InnerContext) -> Result<(), &'static str> {
    pair_version(
        context,
        1,
        ProviderReadinessStatusV1::CredentialMissing,
        "v1",
    )
    .await?;
    pair_version(context, 2, ProviderReadinessStatusV1::Ready, "v2").await?;
    revoke_then_crash_cleanup(context).await?;
    assert_terminal_state(context)
}

async fn pair_version(
    context: &super::support::InnerContext,
    revision: u64,
    initial_status: ProviderReadinessStatusV1,
    label: &str,
) -> Result<(), &'static str> {
    let (mut supervisor, confirmed) = enter_v3(context, initial_status).await?;
    let secret = Zeroizing::new(super::audit::secret_canary(context.root()));
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        revision,
        &command_id,
        format!("revoke-{label}-{command_id}"),
        format!("revoke-{label}-intent"),
    )
    .map_err(|_| "revocation-pair-command")?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(
        command,
        super::audit::ticket_canary(secret.as_slice()),
    )
    .map_err(|_| "revocation-pair-begin")?;
    let mut enrollment = supervisor
        .begin_protected_credential_enrollment(begin)
        .map_err(|_| "revocation-pair-prepare")?;
    let mut handoff = supervisor
        .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::Pair)
        .map_err(|_| "revocation-pair-handoff")?;
    supervisor
        .receive_credential_secret_relay(&mut enrollment)
        .map_err(|_| "revocation-pair-relay")?;
    let relay = enrollment
        .take_relay()
        .ok_or("revocation-pair-relay-take")?;
    handoff
        .take_pair_secret_relay()
        .ok_or("revocation-pair-secret")?
        .seal_and_write(&relay, secret)
        .map_err(|_| "revocation-pair-write")?;
    supervisor
        .finish_protected_credential_enrollment(&mut enrollment, &relay)
        .map_err(|_| "revocation-pair-terminal")?;
    require_completed(&enrollment)?;
    handoff
        .reap_exact_writer()
        .map_err(|_| "revocation-pair-reap")?;
    supervisor
        .stop()
        .map(|_| ())
        .map_err(|_| "revocation-pair-stop")
}

async fn revoke_then_crash_cleanup(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let (mut supervisor, confirmed) = enter_v3(context, ProviderReadinessStatusV1::Ready).await?;
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Revoke,
        ProviderCredentialProviderV2::OpenAi,
        3,
        &command_id,
        format!("revoke-active-{command_id}"),
        "revoke-active-intent",
    )
    .map_err(|_| "revocation-command")?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(
        command,
        super::audit::ticket_canary(b"revoke-control-only"),
    )
    .map_err(|_| "revocation-begin")?;
    let mut enrollment = supervisor
        .begin_protected_credential_enrollment(begin)
        .map_err(|_| "revocation-prepare")?;
    if enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Prepared {
        return Err("revocation-prepared-state");
    }
    let mut revoke_handoff = supervisor
        .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::ControlOnly)
        .map_err(|_| "revocation-handoff")?;
    supervisor
        .finish_control_only_credential_enrollment(&mut enrollment)
        .map_err(|_| "revocation-terminal")?;
    require_completed(&enrollment)?;
    revoke_handoff
        .reap_exact_writer()
        .map_err(|_| "revocation-reap")?;
    let cleanups = supervisor
        .discover_prepared_credential_cleanup()
        .map_err(|_| "revocation-cleanup-discovery")?;
    let [cleanup] = cleanups.as_slice() else {
        return Err("revocation-cleanup-cardinality");
    };
    supervisor
        .stop()
        .map_err(|_| "revocation-post-revoke-stop")?;
    let (mut supervisor, confirmed) =
        enter_v3(context, ProviderReadinessStatusV1::CredentialMissing).await?;
    let recovery = supervisor
        .begin_protected_credential_recovery(*cleanup)
        .map_err(|_| "revocation-cleanup-offer")?;
    let mut cleanup_handoff = supervisor
        .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::ControlOnly)
        .map_err(|_| "revocation-cleanup-handoff")?;
    await_marker(context)?;
    super::native_item::assert_absent(context.root())?;
    super::revocation_state::assert_partial(context, cleanup)?;
    supervisor
        .crash_local_fixture_process()
        .map_err(|_| "revocation-daemon-crash")?;
    release_writer(context)?;
    cleanup_handoff
        .reap_exact_writer_bounded(Duration::from_secs(10))
        .map_err(|_| "revocation-cleanup-reap")?;
    supervisor.stop().map_err(|_| "revocation-crash-stop")?;
    drop(recovery);
    restart_and_reconcile(context).await
}

async fn enter_v3(
    context: &super::support::InnerContext,
    expected: ProviderReadinessStatusV1,
) -> Result<
    (
        super::scoped_cleanup::ScopedSupervisor,
        ConfirmedInstalledNativeEnrollment,
    ),
    &'static str,
> {
    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("revocation-local-admission")?;
    let mut supervisor = context.supervisor()?;
    supervisor.start().map_err(|_| "revocation-runned-start")?;
    let initial = super::support::connect(&mut supervisor, "revocation-initial").await?;
    super::support::require_selected(&initial, expected)?;
    supervisor
        .record_client_ready(&initial)
        .map_err(|_| "revocation-initial-ready")?;
    drop(initial);
    let confirmed = supervisor
        .confirm_installed_native_enrollment(prepared)
        .map_err(|_| "revocation-confirmation")?;
    supervisor
        .begin_credential_enrollment_transition(&confirmed)
        .map_err(|_| "revocation-v3-transition")?;
    let v3 = super::support::connect(&mut supervisor, "revocation-v3").await?;
    supervisor
        .record_client_ready(&v3)
        .map_err(|_| "revocation-v3-ready")?;
    drop(v3);
    super::support::register_credential_service_session(&mut supervisor, &confirmed).await?;
    Ok((supervisor, confirmed))
}

async fn restart_and_reconcile(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (mut supervisor, _) =
        enter_v3(context, ProviderReadinessStatusV1::SecureStoreUnavailable).await?;
    supervisor
        .stop()
        .map(|_| ())
        .map_err(|_| "revocation-recovery-stop")?;
    super::native_item::assert_absent(context.root())
}

fn require_completed(
    enrollment: &runne_platform_desktop::PreparedProtectedCredentialEnrollment,
) -> Result<(), &'static str> {
    (enrollment.terminal()
        && enrollment.snapshot().state() == ProviderCredentialOperationStateV2::Completed)
        .then_some(())
        .ok_or("revocation-not-completed")
}

fn await_marker(context: &super::support::InnerContext) -> Result<(), &'static str> {
    // The packaged recovery handoff may need to relaunch and rejoin the native
    // credential service before the retained writer reaches the crash point.
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        if context.root().join(MARKER).is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("revocation-delete-marker-timeout")
}

fn release_writer(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(context.root().join(RELEASE))
        .map_err(|_| "revocation-delete-release")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.sync_all())
        .map_err(|_| "revocation-delete-release-sync")
}

fn assert_terminal_state(context: &super::support::InnerContext) -> Result<(), &'static str> {
    super::revocation_state::assert_terminal(context)
}

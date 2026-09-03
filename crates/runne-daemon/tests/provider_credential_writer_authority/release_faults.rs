use std::time::Duration;

use super::release_fault_support::{
    assert_no_owned_children, assert_operation_state, require_incomplete, require_not_completed,
    restart_with,
};
use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2, ProviderReadinessStatusV1,
};
use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, CredentialWriterHandoff, CredentialWriterHandoffMode,
    NativeProtectedCredentialEnrollmentBegin, PreparedProtectedCredentialEnrollment,
    ProtectedBundledRuntimeSupervisor,
};

pub(super) fn run() {
    super::harness::dispatch_scenarios(
        "release_faults_and_process_death_remain_truthful_and_reaped",
        &[
            "release-wrong",
            "release-replayed",
            "release-missing",
            "death-prepared",
            "death-claimed",
            "death-released",
            "death-readback",
        ],
        inner,
    );
}

pub(super) fn run_readback() {
    super::harness::dispatch_scenarios(
        "writer_death_readback_recovers_without_replaying_effect",
        &["death-readback"],
        inner,
    );
}

fn inner(context: &super::support::InnerContext, scenario: &str) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "tokio-runtime")?;
    runtime.block_on(async {
        match scenario {
            "death-prepared" => die_prepared(context).await,
            "death-claimed" => die_claimed(context).await,
            "death-readback" => die_readback(context).await,
            "release-wrong" | "release-replayed" | "release-missing" | "death-released" => {
                reject_before_effect(context).await
            }
            _ => Err("unknown-release-fault"),
        }
    })?;
    assert_no_owned_children(context)
}

async fn die_prepared(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (mut supervisor, _) = enter_v3(context).await?;
    let (enrollment, command) = begin_pair(&mut supervisor, "prepared")?;
    if enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Prepared {
        return Err("prepared-state");
    }
    supervisor
        .crash_local_fixture_process()
        .map_err(|_| "prepared-daemon-crash")?;
    supervisor.stop().map_err(|_| "prepared-daemon-stop")?;
    drop(enrollment);
    require_incomplete(context, "PREPARED")?;
    restart_with(
        &mut supervisor,
        context,
        command,
        ProviderReadinessStatusV1::CredentialMissing,
    )
    .await
}

async fn die_claimed(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (mut supervisor, confirmed) = enter_v3(context).await?;
    let (mut enrollment, command) = begin_pair(&mut supervisor, "claimed")?;
    let mut handoff = writer_claim(&mut supervisor, &confirmed, &mut enrollment)?;
    let relay = enrollment.take_relay().ok_or("claimed-relay")?;
    let sealer = handoff.take_pair_secret_relay().ok_or("claimed-sealer")?;
    supervisor
        .crash_local_fixture_process()
        .map_err(|_| "claimed-daemon-crash")?;
    sealer
        .seal_and_write(
            &relay,
            zeroize::Zeroizing::new(super::audit::secret_canary(context.root())),
        )
        .map_err(|_| "claimed-sealed-fd3")?;
    handoff
        .reap_exact_writer_bounded(Duration::from_secs(10))
        .map_err(|_| "claimed-writer-reap")?;
    supervisor.stop().map_err(|_| "claimed-daemon-stop")?;
    require_incomplete(context, "CLAIMED")?;
    restart_with(
        &mut supervisor,
        context,
        command,
        ProviderReadinessStatusV1::CredentialMissing,
    )
    .await
}

async fn reject_before_effect(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (mut supervisor, confirmed) = enter_v3(context).await?;
    let (mut enrollment, command) = begin_pair(&mut supervisor, "release")?;
    let mut handoff = match writer_claim(&mut supervisor, &confirmed, &mut enrollment) {
        Ok(handoff) => handoff,
        Err("writer-handoff") => {
            let _ = supervisor.abort_protected_credential_enrollment();
            let _ = supervisor.stop();
            require_not_completed(context)?;
            return super::native_item::assert_absent(context.root());
        }
        Err(error) => return Err(error),
    };
    let relay = enrollment.take_relay().ok_or("release-relay")?;
    handoff
        .take_pair_secret_relay()
        .ok_or("release-sealer")?
        .seal_and_write(
            &relay,
            zeroize::Zeroizing::new(super::audit::secret_canary(context.root())),
        )
        .map_err(|_| "release-sealed-fd3")?;
    if supervisor
        .finish_protected_credential_enrollment(&mut enrollment, &relay)
        .is_ok()
    {
        return Err("faulted-release-completed");
    }
    handoff
        .reap_exact_writer_bounded(Duration::from_secs(10))
        .map_err(|_| "release-writer-reap")?;
    let _ = supervisor.stop();
    require_incomplete(context, "CLAIMED")?;
    restart_with(
        &mut supervisor,
        context,
        command,
        ProviderReadinessStatusV1::CredentialMissing,
    )
    .await
}

async fn die_readback(context: &super::support::InnerContext) -> Result<(), &'static str> {
    let (mut supervisor, confirmed) = enter_v3(context).await?;
    let (mut enrollment, command) = begin_pair(&mut supervisor, "readback")?;
    let mut handoff = writer_claim(&mut supervisor, &confirmed, &mut enrollment)?;
    let relay = enrollment.take_relay().ok_or("readback-relay")?;
    handoff
        .take_pair_secret_relay()
        .ok_or("readback-sealer")?
        .seal_and_write(
            &relay,
            zeroize::Zeroizing::new(super::audit::secret_canary(context.root())),
        )
        .map_err(|_| "readback-sealed-fd3")?;
    if supervisor
        .finish_protected_credential_enrollment(&mut enrollment, &relay)
        .is_ok()
    {
        return Err("readback-daemon-survived");
    }
    handoff
        .reap_exact_writer_bounded(Duration::from_secs(10))
        .map_err(|_| "readback-writer-reap")?;
    supervisor.stop().map_err(|_| "readback-daemon-stop")?;
    assert_operation_state(context, "NATIVE_EFFECT_OBSERVED")?;
    restart_with(
        &mut supervisor,
        context,
        command,
        ProviderReadinessStatusV1::Ready,
    )
    .await?;
    super::support::assert_durable_counts(context.runtime_root())
}

async fn enter_v3(
    context: &super::support::InnerContext,
) -> Result<
    (
        ProtectedBundledRuntimeSupervisor,
        ConfirmedInstalledNativeEnrollment,
    ),
    &'static str,
> {
    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("local-admission")?;
    let mut supervisor = context.supervisor()?;
    supervisor.start().map_err(|_| "initial-runned-start")?;
    let client = super::support::connect(&mut supervisor, "fault-initial").await?;
    super::support::require_selected(&client, ProviderReadinessStatusV1::CredentialMissing)?;
    supervisor
        .record_client_ready(&client)
        .map_err(|_| "initial-ready")?;
    drop(client);
    let confirmed = supervisor
        .confirm_installed_native_enrollment(prepared)
        .map_err(|_| "local-confirmation")?;
    supervisor
        .begin_credential_enrollment_transition(&confirmed)
        .map_err(|_| "v3-transition")?;
    let v3 = super::support::connect(&mut supervisor, "fault-v3").await?;
    supervisor
        .record_client_ready(&v3)
        .map_err(|_| "v3-ready")?;
    drop(v3);
    super::support::register_credential_service_session(&mut supervisor, &confirmed).await?;
    Ok((supervisor, confirmed))
}

fn begin_pair(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    label: &str,
) -> Result<
    (
        PreparedProtectedCredentialEnrollment,
        BeginProviderCredentialEnrollment,
    ),
    &'static str,
> {
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        &command_id,
        format!("slice-e-{label}-{command_id}"),
        "slice-e-release-fault-intent",
    )
    .map_err(|_| "begin-command")?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(command.clone(), [79; 32])
        .map_err(|_| "native-begin")?;
    supervisor
        .begin_protected_credential_enrollment(begin)
        .map(|enrollment| (enrollment, command))
        .map_err(|_| "protected-begin")
}

fn writer_claim(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
    confirmed: &ConfirmedInstalledNativeEnrollment,
    enrollment: &mut PreparedProtectedCredentialEnrollment,
) -> Result<CredentialWriterHandoff, &'static str> {
    let handoff = supervisor
        .run_credential_writer_handoff(confirmed, CredentialWriterHandoffMode::Pair)
        .inspect_err(|error| {
            use runne_platform_desktop::ProtectedBundledRuntimeError as Error;
            let category = match error {
                Error::OwnershipMismatch => "ownership",
                Error::InvalidState => "state",
                Error::ProtectedChannelUnavailable => "channel",
                Error::ReadinessTimeout => "readiness",
                Error::SpawnFailed => "spawn",
                Error::ExecutableIdentityMismatch => "identity",
                _ => "other-closed-category",
            };
            eprintln!("writer-handoff-category={category}");
        })
        .map_err(|_| "writer-handoff")?;
    supervisor
        .receive_credential_secret_relay(enrollment)
        .map_err(|_| "secret-relay")?;
    Ok(handoff)
}

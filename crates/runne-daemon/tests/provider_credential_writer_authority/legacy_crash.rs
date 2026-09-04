use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use runne_api::ProviderReadinessStatusV1;
use runne_platform_desktop::{ConfirmedInstalledNativeEnrollment, CredentialWriterHandoffMode};

const DELETE_MARKER: &str = "legacy-source-delete.marker";
const DELETE_RELEASE: &str = "legacy-source-delete.release";

pub(super) fn await_post_delete_barrier(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let (marker, _) = barrier_paths(context.root());
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if marker.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("legacy-delete-marker-timeout")
}

pub(super) fn release_post_delete_writer(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    create_release(context.root())
}

fn create_release(root: &Path) -> Result<(), &'static str> {
    let (_, release) = barrier_paths(root);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(release)
        .map_err(|_| "legacy-delete-release")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| "legacy-delete-release-mode")?;
    file.sync_all().map_err(|_| "legacy-delete-release-sync")
}

pub(super) fn barrier_paths(root: &Path) -> (PathBuf, PathBuf) {
    (root.join(DELETE_MARKER), root.join(DELETE_RELEASE))
}

pub(super) fn crash_stage(
    context: &super::support::InnerContext,
) -> Result<super::legacy_evidence::LegacyCleanupEvidence, &'static str> {
    super::legacy_scenario::import_stage(context)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "tokio-runtime")?;
    runtime.block_on(crash_and_reconcile(context))
}

async fn crash_and_reconcile(
    context: &super::support::InnerContext,
) -> Result<super::legacy_evidence::LegacyCleanupEvidence, &'static str> {
    let operation = cleanup_operation_id(context)?;
    let (mut supervisor, confirmed) = enter_v3(context).await?;
    let recovery = supervisor
        .begin_protected_credential_recovery(operation)
        .map_err(|_| "cleanup-recovery-offer")?;
    let mut handoff = supervisor
        .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::ControlOnly)
        .map_err(|_| "cleanup-writer-handoff")?;
    await_post_delete_barrier(context)?;
    super::legacy_crash_readback::assert_exact_legacy_source_absent(context)?;
    assert_cleanup_state(context, "CLAIMED")?;
    assert_cleanup_has_no_completion_receipt(context)?;
    let deleted_observation =
        super::legacy_observations::operation(context, "LEGACY_SOURCE_CLEANUP", "CLAIMED")?;
    supervisor
        .crash_local_fixture_process()
        .map_err(|_| "cleanup-daemon-crash")?;
    release_post_delete_writer(context)?;
    handoff
        .reap_exact_writer_bounded(Duration::from_secs(10))
        .map_err(|_| "cleanup-writer-reap")?;
    supervisor.stop().map_err(|_| "cleanup-daemon-stop")?;
    drop(recovery);
    assert_cleanup_state(context, "CLAIMED")?;
    assert_cleanup_has_no_completion_receipt(context)?;

    restart_and_reconcile(&mut supervisor).await?;
    super::legacy_crash_readback::assert_exact_legacy_source_absent(context)?;
    assert_cleanup_completed_and_consumed(context, operation)?;
    assert_recovery_replay_is_rejected(context, operation).await?;
    let reimport_observation =
        super::legacy_crash_reimport::assert_fresh_migrate_is_rejected(context).await?;
    let mut evidence = super::legacy_evidence::LegacyCleanupEvidence::default();
    evidence.record(
        super::legacy_evidence::EXACT_SOURCE_DELETED,
        &deleted_observation,
    );
    evidence.record(
        super::legacy_evidence::RESTART_AFTER_DELETE,
        &super::legacy_observations::operation(context, "LEGACY_SOURCE_CLEANUP", "TOMBSTONED")?,
    );
    evidence.record(
        super::legacy_evidence::REIMPORT_DENIED,
        &reimport_observation,
    );
    Ok(evidence)
}

pub(super) async fn enter_v3(
    context: &super::support::InnerContext,
) -> Result<
    (
        super::scoped_cleanup::ScopedSupervisor,
        ConfirmedInstalledNativeEnrollment,
    ),
    &'static str,
> {
    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("cleanup-local-admission")?;
    let mut supervisor = context.supervisor()?;
    supervisor.start().map_err(|_| "cleanup-runned-start")?;
    let initial = super::support::connect(&mut supervisor, "cleanup-initial").await?;
    super::support::require_selected(&initial, ProviderReadinessStatusV1::Ready)?;
    supervisor
        .record_client_ready(&initial)
        .map_err(|_| "cleanup-initial-ready")?;
    drop(initial);
    let confirmed = supervisor
        .confirm_installed_native_enrollment(prepared)
        .map_err(|_| "cleanup-local-confirmation")?;
    supervisor
        .begin_credential_enrollment_transition(&confirmed)
        .map_err(|_| "cleanup-v3-transition")?;
    let v3 = super::support::connect(&mut supervisor, "cleanup-v3").await?;
    supervisor
        .record_client_ready(&v3)
        .map_err(|_| "cleanup-v3-ready")?;
    drop(v3);
    super::support::register_credential_service_session(&mut supervisor, &confirmed).await?;
    Ok((supervisor, confirmed))
}

async fn restart_and_reconcile(
    supervisor: &mut super::scoped_cleanup::ScopedSupervisor,
) -> Result<(), &'static str> {
    supervisor.start().map_err(|_| "cleanup-restart")?;
    let client = super::support::connect(supervisor, "cleanup-restart").await?;
    super::support::require_selected(&client, ProviderReadinessStatusV1::Ready)?;
    supervisor
        .record_client_ready(&client)
        .map_err(|_| "cleanup-restart-ready")?;
    drop(client);
    supervisor.stop().map_err(|_| "cleanup-restart-stop")?;
    Ok(())
}

async fn assert_recovery_replay_is_rejected(
    context: &super::support::InnerContext,
    operation: [u8; 16],
) -> Result<(), &'static str> {
    let (mut supervisor, _) = enter_v3(context).await?;
    if supervisor
        .begin_protected_credential_recovery(operation)
        .is_ok()
    {
        return Err("cleanup-recovery-replayed");
    }
    supervisor
        .stop()
        .map(|_| ())
        .map_err(|_| "cleanup-replay-stop")
}

pub(super) fn cleanup_operation_id(
    context: &super::support::InnerContext,
) -> Result<[u8; 16], &'static str> {
    let operation: Vec<u8> = super::legacy_observations::database(context)?
        .query_row(
            "SELECT operation_id FROM provider_credential_operations WHERE action='LEGACY_SOURCE_CLEANUP'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "cleanup-operation-id")?;
    operation
        .try_into()
        .map_err(|_| "cleanup-operation-id-shape")
}

fn assert_cleanup_state(
    context: &super::support::InnerContext,
    expected: &str,
) -> Result<(), &'static str> {
    let state: String = super::legacy_observations::database(context)?
        .query_row(
            "SELECT state FROM provider_credential_operations WHERE action='LEGACY_SOURCE_CLEANUP'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "cleanup-state")?;
    (state == expected)
        .then_some(())
        .ok_or("cleanup-state-mismatch")
}

/// Proves the crash happened after the native effect but before any durable
/// completion: no completion receipt may exist for the claimed cleanup.
fn assert_cleanup_has_no_completion_receipt(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let receipts: i64 = super::legacy_observations::database(context)?
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_completion_receipts
             WHERE operation_id=(SELECT operation_id FROM provider_credential_operations
                 WHERE action='LEGACY_SOURCE_CLEANUP')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "cleanup-pre-crash-receipt")?;
    (receipts == 0)
        .then_some(())
        .ok_or("cleanup-completed-before-crash")
}

fn assert_cleanup_completed_and_consumed(
    context: &super::support::InnerContext,
    operation: [u8; 16],
) -> Result<(), &'static str> {
    let connection = super::legacy_observations::database(context)?;
    let receipts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_completion_receipts WHERE operation_id=?1 AND readback_disposition='EXACT_ABSENCE'",
            [operation.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| "cleanup-receipt")?;
    let (state, consumed, imports, cleanups): (String, i64, i64, i64) = connection
        .query_row(
            "SELECT operation.state, head.legacy_import_consumed,
                    (SELECT COUNT(*) FROM provider_credential_operations WHERE action='MIGRATE_LEGACY'),
                    (SELECT COUNT(*) FROM provider_credential_operations WHERE action='LEGACY_SOURCE_CLEANUP')
             FROM provider_credential_operations AS operation
             JOIN provider_credential_authority_heads AS head ON head.provider_id=operation.provider_id
             WHERE operation.operation_id=?1",
            [operation.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "cleanup-completion")?;
    (state == "TOMBSTONED" && consumed == 1 && receipts == 1 && imports == 1 && cleanups == 1)
        .then_some(())
        .ok_or("cleanup-completion-or-consumption")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_barrier_paths_are_confined_to_the_disposable_fixture_root() {
        let root = Path::new("/private/tmp/runne-fixture");
        let (marker, release) = barrier_paths(root);
        assert_eq!(marker, root.join("legacy-source-delete.marker"));
        assert_eq!(release, root.join("legacy-source-delete.release"));
    }

    #[test]
    fn crash_barrier_release_is_single_use_and_private() {
        let temporary = tempfile::tempdir().expect("temporary fixture root");
        create_release(temporary.path()).expect("first release");
        let (_, release) = barrier_paths(temporary.path());
        assert_eq!(
            std::fs::metadata(&release)
                .expect("release metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(create_release(temporary.path()).is_err());
    }
}

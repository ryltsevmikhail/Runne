//! Dedicated legacy import/cutover/delete/crash native scenario.
//!
//! The scenario runs only under the disposable Keychain rig on an isolated
//! darwin arm64 host through the pinned `--ignored` invocation. Every stage
//! either executes the real production path or fails closed with a named
//! error, so a green result is impossible without the real chain.

use super::legacy_evidence::{
    LEGACY_CLEANUP_CANDIDATE_ENV, LEGACY_CLEANUP_EVIDENCE_ENV, LEGACY_CLEANUP_RUN_ID_ENV,
    LEGACY_CLEANUP_TUPLE_ENV, is_evidence_digest_shape, is_evidence_run_id_shape,
};
use super::support::InnerContext;
use zeroize::Zeroizing;

pub(super) fn run() {
    super::harness::dispatch_legacy_scenarios(
        "legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone",
        inner,
    );
}

fn inner(
    context: &InnerContext,
    scenario: &str,
) -> Result<super::legacy_evidence::LegacyCleanupEvidence, &'static str> {
    scenario_binding_from_environment();
    match scenario {
        "legacy-import" => {
            import_stage(context)?;
            let mut evidence = super::legacy_evidence::LegacyCleanupEvidence::default();
            evidence.record(
                super::legacy_evidence::AUTHORIZED_IMPORT,
                &super::legacy_observations::import(context)?,
            );
            evidence.record(
                super::legacy_evidence::DURABLE_CUTOVER,
                &super::legacy_observations::cutover(context)?,
            );
            Ok(evidence)
        }
        "legacy-crash-delete" => super::legacy_crash::crash_stage(context),
        "legacy-replacement-denied" => super::legacy_denial::replacement_stage(context),
        "legacy-ambiguous-denied" => super::legacy_denial::ambiguous_stage(context),
        _ => Err("unknown-legacy-scenario"),
    }
}

/// Reserved transcript for a future versioned profile with a real historical
/// source. D1.1a dispatch rejects before native setup; no seed producer exists.
pub(super) fn import_stage(context: &InnerContext) -> Result<(), &'static str> {
    assert_untrusted_child_is_denied(context)?;
    assert_seeded_item_is_visible();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "tokio-runtime")?;
    runtime.block_on(migrate_transcript(context))?;
    assert_durable_migrate_state(context)
}

/// Negative control: this packaged scenario process is not the staged writer,
/// so the exact ACL must deny both direct seeding and direct reads.
fn assert_untrusted_child_is_denied(context: &InnerContext) -> Result<(), &'static str> {
    use runne_secure_store::{
        NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
        ProviderCredentialMaterial, ProviderCredentialStore,
    };
    let store = NativeProviderCredentialStore::new();
    let access = ProviderCredentialAccessPolicy::new(&context.writer(), context.daemon())
        .map_err(|_| "seed-access-policy")?;
    let exact =
        runne_macos_keychain_acl::ExactKeychainAccess::new(&context.writer(), context.daemon())
            .map_err(|_| "seed-exact-access")?;
    let material = ProviderCredentialMaterial::new(super::audit::secret_canary(context.root()))
        .map_err(|_| "seed-material")?;
    let seed_attempt = store.seed_generation_zero_source_scenario(
        ProviderCredentialId::OpenAi,
        &material,
        &access,
        &exact,
        scenario_revision()?,
    );
    match &seed_attempt {
        Err(runne_secure_store::SecureStoreError::CredentialAccessDenied) => {}
        _ => return Err("seed-negative-denial-missing"),
    }
    let read_attempt = store.load_provider_credential(ProviderCredentialId::OpenAi, &access);
    assert!(
        read_attempt.is_err(),
        "untrusted scenario process must not read the legacy source"
    );
    Ok(())
}

async fn migrate_transcript(context: &InnerContext) -> Result<(), &'static str> {
    use runne_api::{
        BeginProviderCredentialEnrollment, ProviderCredentialEnrollmentActionV2,
        ProviderCredentialOperationStateV2, ProviderCredentialProviderV2,
        ProviderReadinessStatusV1,
    };
    use runne_platform_desktop::{
        CredentialWriterHandoffMode, NativeProtectedCredentialEnrollmentBegin,
    };

    let prepared = runne_platform_desktop::prepare_local_native_enrollment(context.profile())
        .ok_or("local-admission")?;
    let mut supervisor = context.supervisor()?;
    supervisor.start().map_err(|_| "initial-runned-start")?;
    let initial = super::support::connect(&mut supervisor, "initial").await?;
    // The seeded generation-0 source is a committed slot: the daemon reader
    // reports the provider Ready before the migration begins.
    super::support::require_selected(&initial, ProviderReadinessStatusV1::Ready)?;
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
    let v3 = super::support::connect(&mut supervisor, "v3").await?;
    supervisor
        .record_client_ready(&v3)
        .map_err(|_| "v3-ready")?;
    drop(v3);
    super::support::register_credential_service_session(&mut supervisor, &confirmed).await?;

    let secret = Zeroizing::new(super::audit::secret_canary(context.root()));
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::MigrateLegacy,
        ProviderCredentialProviderV2::OpenAi,
        1,
        &command_id,
        format!("slice-e-migrate-{command_id}"),
        "slice-e-migrate-intent",
    )
    .map_err(|_| "begin-command")?;
    let begin = NativeProtectedCredentialEnrollmentBegin::new(
        command,
        super::audit::ticket_canary(secret.as_slice()),
    )
    .map_err(|_| "native-begin")?;
    let mut enrollment = supervisor
        .begin_protected_credential_enrollment(begin)
        .map_err(|_| "protected-begin")?;
    if enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Prepared {
        return Err("prepared-state");
    }
    let mut handoff = supervisor
        .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::ControlOnly)
        .map_err(|_| "writer-handoff")?;
    // Control-only claimed effects carry no secret relay, so no relay receive
    // or acknowledgement precedes the terminal evidence.
    supervisor
        .finish_control_only_credential_enrollment(&mut enrollment)
        .map_err(|_| "control-only-terminal")?;
    if !enrollment.terminal()
        || enrollment.snapshot().state() != ProviderCredentialOperationStateV2::Completed
    {
        return Err("terminal-state");
    }
    handoff.reap_exact_writer().map_err(|_| "writer-reap")?;
    supervisor.stop().map_err(|_| "first-runned-stop")?;
    Ok(())
}

/// The durable cutover must be committed before any cleanup runs: the import
/// operation is COMPLETED, the head carries the consumed legacy linkage, the
/// linked cleanup operation is only PREPARED, and the legacy item is intact.
fn assert_durable_migrate_state(context: &InnerContext) -> Result<(), &'static str> {
    let database = context.runtime_root().join("runne-daemon/event-log.db");
    let connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "sqlite-open")?;
    let mut operations = connection
        .prepare("SELECT action, state FROM provider_credential_operations ORDER BY action")
        .map_err(|_| "sqlite-prepare")?;
    let rows = operations
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| "sqlite-query")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "sqlite-row")?;
    drop(operations);
    if rows
        != vec![
            ("LEGACY_SOURCE_CLEANUP".to_string(), "PREPARED".to_string()),
            ("MIGRATE_LEGACY".to_string(), "COMPLETED".to_string()),
        ]
    {
        return Err("durable-operations");
    }
    type LegacyHeadRow = (i64, Option<Vec<u8>>, Option<i64>, Option<Vec<u8>>);
    let (consumed, digest, revision, cleanup): LegacyHeadRow = connection
        .query_row(
            "SELECT legacy_import_consumed, legacy_source_binding_digest,
                        legacy_consumed_lifecycle_revision, legacy_cleanup_operation_id
                 FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "sqlite-head")?;
    if consumed != 1
        || digest.is_none_or(|value| value.iter().all(|byte| *byte == 0))
        || revision != Some(2)
        || cleanup.is_none()
    {
        return Err("durable-cutover-linkage");
    }
    assert_seeded_item_is_visible();
    Ok(())
}

/// The seeded item must be findable by its exact service and account identity.
/// The fixed nonzero source revision every legacy fixture seeds.
pub(super) fn scenario_revision()
-> Result<runne_secure_store::ProviderCredentialSourceRevision, &'static str> {
    runne_secure_store::ProviderCredentialSourceRevision::new([
        0x5c, 0x4a, 0x11, 0xf2, 0x9d, 0x63, 0xb8, 0x27, 0x40, 0x71, 0xe5, 0x0a, 0xd3, 0x96, 0x18,
        0x6f,
    ])
    .map_err(|_| "seed-revision")
}

fn assert_seeded_item_is_visible() {
    let keychain = scenario_keychain();
    let metadata = runne_macos_keychain_acl::find_generic_password_metadata(
        &keychain,
        runne_secure_store::PROVIDER_CREDENTIAL_SERVICE,
        runne_secure_store::ProviderCredentialId::OpenAi.account(),
    )
    .expect("seeded item lookup")
    .expect("seeded generation-0 item must exist");
    assert!(!metadata.bytes.is_empty(), "seeded metadata is empty");
}

pub(super) fn scenario_keychain() -> security_framework::os::macos::keychain::SecKeychain {
    let home = std::env::var_os("HOME").expect("scenario HOME");
    let path = std::path::PathBuf::from(home).join("Library/Keychains/runne-ci.keychain-db");
    security_framework::os::macos::keychain::SecKeychain::open(&path)
        .expect("scenario disposable keychain")
}

fn scenario_binding_from_environment() {
    let evidence_path = std::env::var_os(LEGACY_CLEANUP_EVIDENCE_ENV)
        .ok_or("scenario binding is missing the evidence path")
        .expect("scenario evidence path binding");
    assert!(
        !std::path::PathBuf::from(&evidence_path).exists(),
        "scenario evidence path must not exist before the run"
    );
    let read = |name: &'static str| -> String {
        match std::env::var(name) {
            Ok(value) => value,
            Err(_) => panic!("scenario binding is missing {name}"),
        }
    };
    let candidate_sha256 = read(LEGACY_CLEANUP_CANDIDATE_ENV);
    let tuple_sha256 = read(LEGACY_CLEANUP_TUPLE_ENV);
    let workflow_run_id = read(LEGACY_CLEANUP_RUN_ID_ENV);
    assert!(
        is_evidence_digest_shape(&candidate_sha256) && is_evidence_digest_shape(&tuple_sha256),
        "scenario candidate or tuple binding is invalid"
    );
    assert!(
        is_evidence_run_id_shape(&workflow_run_id),
        "scenario workflow identity is invalid"
    );
}

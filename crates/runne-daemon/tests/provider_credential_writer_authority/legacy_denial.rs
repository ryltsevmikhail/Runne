//! Denial fixtures for the legacy cleanup chain: a replaced source revision
//! and an ambiguous second slot must both fail the native deletion without
//! any mutation, receipt or tombstone. The denial proof is the retained
//! native state plus the durable non-terminal cleanup, never the transport
//! error alone.

use std::time::Duration;

use runne_platform_desktop::CredentialWriterHandoffMode;
use runne_secure_store::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial,
};

use super::legacy_evidence::{AMBIGUOUS_SOURCE_DENIED, LegacyCleanupEvidence, REPLACEMENT_DENIED};
use super::support::InnerContext;

const ROTATED_GENERATION: u64 = 1;

/// Rotation after cutover: exactly one valid committed source with a
/// different revision survives the denied cleanup.
pub(super) fn replacement_stage(
    context: &InnerContext,
) -> Result<LegacyCleanupEvidence, &'static str> {
    super::legacy_scenario::import_stage(context)?;
    rotate_native_source(context)?;
    run_denied_cleanup(context)?;
    let operation = super::legacy_crash::cleanup_operation_id(context)?;
    assert_retained(true, false)?;
    assert_cleanup_denied_durably(context)?;
    let mut evidence = LegacyCleanupEvidence::default();
    evidence.record(
        REPLACEMENT_DENIED,
        &format!(
            "replacement-denied:{}:alternate-retained:{}",
            hex::encode(operation),
            hex::encode(super::legacy_scenario::scenario_revision()?.as_bytes())
        ),
    );
    Ok(evidence)
}

/// Ambiguity: a second valid committed slot claims the binding's revision, so
/// both slots survive without any partial deletion.
pub(super) fn ambiguous_stage(
    context: &InnerContext,
) -> Result<LegacyCleanupEvidence, &'static str> {
    super::legacy_scenario::import_stage(context)?;
    seed_ambiguous_alternate(context)?;
    run_denied_cleanup(context)?;
    let operation = super::legacy_crash::cleanup_operation_id(context)?;
    assert_retained(true, true)?;
    assert_cleanup_denied_durably(context)?;
    let mut evidence = LegacyCleanupEvidence::default();
    evidence.record(
        AMBIGUOUS_SOURCE_DENIED,
        &format!(
            "ambiguous-denied:{}:primary-retained:alternate-retained",
            hex::encode(operation)
        ),
    );
    Ok(evidence)
}

/// Replaces the imported generation-zero source with one committed
/// alternate-slot item of a different revision, exactly as a native rotation
/// would leave the store.
fn rotate_native_source(context: &InnerContext) -> Result<(), &'static str> {
    let replacement = hex::encode(b"replacement-source-revision-v2");
    let mut revision = [0u8; 16];
    revision.copy_from_slice(&replacement.as_bytes()[..16]);
    let revision = runne_secure_store::ProviderCredentialSourceRevision::new(revision)
        .map_err(|_| "replacement-revision")?;
    seed_committed_slot(context, true, revision)?;
    let store = NativeProviderCredentialStore::new();
    store
        .remove_source_slot_scenario(ProviderCredentialId::OpenAi, false)
        .map_err(|_| "replacement-remove-legacy")?;
    assert_item("primary", false)?;
    assert_item("alternate", true)
}

/// Adds a second valid committed slot item carrying the binding's revision.
fn seed_ambiguous_alternate(context: &InnerContext) -> Result<(), &'static str> {
    seed_committed_slot(context, true, super::legacy_scenario::scenario_revision()?)?;
    assert_item("primary", true)?;
    assert_item("alternate", true)
}

fn seed_committed_slot(
    context: &InnerContext,
    alternate: bool,
    revision: runne_secure_store::ProviderCredentialSourceRevision,
) -> Result<(), &'static str> {
    use runne_secure_store::ScenarioSourceSlotSeed;

    let store = NativeProviderCredentialStore::new();
    let access = ProviderCredentialAccessPolicy::new(&context.writer(), context.daemon())
        .map_err(|_| "denial-access-policy")?;
    let exact =
        runne_macos_keychain_acl::ExactKeychainAccess::new(&context.writer(), context.daemon())
            .map_err(|_| "denial-exact-access")?;
    let material = ProviderCredentialMaterial::new(super::audit::secret_canary(context.root()))
        .map_err(|_| "denial-material")?;
    store
        .seed_committed_source_slot_scenario(
            ProviderCredentialId::OpenAi,
            &ScenarioSourceSlotSeed {
                alternate,
                generation: ROTATED_GENERATION,
            },
            &material,
            &access,
            &exact,
            revision,
        )
        .map_err(|_| "denial-seed-slot")?;
    Ok(())
}

/// Drives the production prepared-cleanup recovery and its ControlOnly
/// writer; the native denial surfaces as a missing terminal delivery.
fn run_denied_cleanup(context: &InnerContext) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "denial-tokio-runtime")?;
    runtime.block_on(async {
        let (mut supervisor, confirmed) = super::legacy_crash::enter_v3(context).await?;
        let operation = super::legacy_crash::cleanup_operation_id(context)?;
        let recovery = supervisor
            .begin_protected_credential_recovery(operation)
            .map_err(|_| "denial-recovery-offer")?;
        let mut handoff = supervisor
            .run_credential_writer_handoff(&confirmed, CredentialWriterHandoffMode::ControlOnly)
            .map_err(|_| "denial-writer-handoff")?;
        let finish = supervisor.finish_protected_credential_recovery(recovery);
        // The writer denied the native deletion, so the daemon cannot deliver
        // terminal evidence. Any success here means the fixture did not reach
        // the denial branch.
        if finish.is_ok() {
            return Err("denial-unexpected-terminal");
        }
        handoff
            .reap_exact_writer_bounded(Duration::from_secs(10))
            .map_err(|_| "denial-writer-reap")?;
        supervisor.stop().map_err(|_| "denial-daemon-stop")?;
        Ok(())
    })
}

fn assert_retained(alternate: bool, primary: bool) -> Result<(), &'static str> {
    assert_item("alternate", alternate)?;
    assert_item("primary", primary)
}

/// One retained native item check by exact service and account identity.
fn assert_item(slot: &str, expected_present: bool) -> Result<(), &'static str> {
    let keychain = super::legacy_scenario::scenario_keychain();
    let service = match slot {
        "primary" => runne_secure_store::PROVIDER_CREDENTIAL_SERVICE.to_string(),
        _ => format!(
            "{}.source-alternate",
            runne_secure_store::PROVIDER_CREDENTIAL_SERVICE
        ),
    };
    let present = runne_macos_keychain_acl::find_generic_password_metadata(
        &keychain,
        &service,
        runne_secure_store::ProviderCredentialId::OpenAi.account(),
    )
    .map_err(|_| "denial-item-lookup")?
    .is_some();
    (present == expected_present)
        .then_some(())
        .ok_or("denial-item-retention")
}

/// The durable denial: the cleanup operation stays non-terminal with no
/// completion receipt, and the consumed head keeps its original linkage.
fn assert_cleanup_denied_durably(context: &InnerContext) -> Result<(), &'static str> {
    let connection = super::legacy_observations::database(context)?;
    let (state, receipts): (String, i64) = connection
        .query_row(
            "SELECT operation.state,
                    (SELECT COUNT(*) FROM provider_credential_completion_receipts
                     WHERE operation_id=operation.operation_id)
             FROM provider_credential_operations AS operation
             WHERE operation.action='LEGACY_SOURCE_CLEANUP'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "denial-durable-query")?;
    if state != "CLAIMED" || receipts != 0 {
        return Err("denial-durable-state");
    }
    let (consumed, digest, cleanup): (i64, Option<Vec<u8>>, Option<Vec<u8>>) = connection
        .query_row(
            "SELECT legacy_import_consumed, legacy_source_binding_digest,
                    legacy_cleanup_operation_id
             FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "denial-head-query")?;
    if consumed != 1 || digest.is_none() || cleanup.is_none() {
        return Err("denial-head-linkage");
    }
    Ok(())
}

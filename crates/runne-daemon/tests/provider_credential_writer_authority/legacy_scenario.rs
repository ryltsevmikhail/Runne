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

pub(super) fn run() {
    super::harness::dispatch_scenarios(
        "legacy_cleanup_scenario_chain_completes_import_cutover_delete_crash_and_tombstone",
        &["import"],
        inner,
    );
}

fn inner(context: &InnerContext, scenario: &str) -> Result<(), &'static str> {
    scenario_binding_from_environment();
    match scenario {
        "import" => import_stage(context),
        _ => Err("unknown-legacy-scenario"),
    }
}

/// Seeds the generation-0 legacy source, then drives the production daemon
/// MigrateLegacy transcript to its durable cutover.
fn import_stage(context: &InnerContext) -> Result<(), &'static str> {
    seed_legacy_source(context)?;
    // The daemon transcript stages (ControlOnly handoff, authorized import,
    // durable cutover, atomic PREPARED cleanup) are wired in the next slice.
    // Refuse rather than pass without them.
    Err("migrate-transcript-stage-not-implemented")
}

fn seed_legacy_source(context: &InnerContext) -> Result<(), &'static str> {
    use runne_secure_store::{
        NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
        ProviderCredentialMaterial, ProviderCredentialSourceRevision,
    };
    let store = NativeProviderCredentialStore::new();
    let access = ProviderCredentialAccessPolicy::new(&context.writer(), context.daemon())
        .map_err(|_| "seed-access-policy")?;
    let exact =
        runne_macos_keychain_acl::ExactKeychainAccess::new(&context.writer(), context.daemon())
            .map_err(|_| "seed-exact-access")?;
    let material = ProviderCredentialMaterial::new(super::audit::secret_canary(context.root()))
        .map_err(|_| "seed-material")?;
    let revision = ProviderCredentialSourceRevision::new([
        0x5c, 0x4a, 0x11, 0xf2, 0x9d, 0x63, 0xb8, 0x27, 0x40, 0x71, 0xe5, 0x0a, 0xd3, 0x96, 0x18,
        0x6f,
    ])
    .map_err(|_| "seed-revision")?;
    store
        .seed_generation_zero_source_scenario(
            ProviderCredentialId::OpenAi,
            &material,
            &access,
            &exact,
            revision,
        )
        .map_err(|_| "seed-generation-zero")?;
    assert_seeded_item_is_visible();
    Ok(())
}

/// The seeded item must be findable by its exact service and account identity.
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

fn scenario_keychain() -> security_framework::os::macos::keychain::SecKeychain {
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

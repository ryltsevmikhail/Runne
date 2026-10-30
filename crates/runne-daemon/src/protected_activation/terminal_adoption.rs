//! Offline, explicit owner adoption; never invoked by ordinary daemon startup.
use std::path::{Path, PathBuf};

use runne_api::StableRuntimeBindingV1;
use serde::Serialize;

use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
use crate::error::DaemonError;
use crate::terminal_image_policy::ImagePolicy;

mod credential;
mod fresh;
mod journal;
pub use credential::credential_access;
pub use fresh::{InstallationStatus, initialize_fresh, inspect};
mod image_upgrade;
pub use image_upgrade::upgrade_images;
mod repin;
pub use repin::repin_tools;

/// Non-secret exact target presented before owner consent.
#[derive(Debug, Serialize)]
pub struct TerminalAdoptionPreview {
    pub runtime_root: PathBuf,
    pub manifest: String,
    pub provider_profile: String,
    pub already_adopted: bool,
}

/// Measures the installed CLI/daemon/credential-host tuple without starting services.
pub fn prepare() -> Result<TerminalAdoptionPreview, DaemonError> {
    let (config, images, root) = verified_target()?;
    images.revalidate().map_err(failure)?;
    let already_adopted = adopted(&config, &root)?;
    Ok(TerminalAdoptionPreview {
        runtime_root: root,
        manifest: hex::encode(images.manifest),
        already_adopted,
        provider_profile: config.provider_activation.binding().profile_id().to_owned(),
    })
}

/// Repins the installation source to the exact binaries in `directory`.
///
/// Explicit stopped-runtime command for a rebuilt CLI/daemon pair whose
/// configuration, authority and database are unchanged. The previous source
/// record is retained beside the new one; no database or credential is touched.
pub fn pin_source(directory: &Path) -> Result<InstallationStatus, DaemonError> {
    let config = crate::config::load_external_config()?;
    let database = Path::new(&config.db_path);
    let root = database
        .parent()
        .and_then(Path::parent)
        .filter(|root| root.is_absolute())
        .ok_or_else(|| failure("pinned runtime layout unavailable"))?;
    let config_path = crate::config::external_config_path();
    let cli = std::fs::canonicalize(directory.join("runne"))
        .map_err(|_| failure("pinned CLI image unavailable"))?;
    let daemon = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| failure("pinned daemon image unavailable"))?;
    let record = root
        .join(".desktop-protected-activation")
        .join("terminal-installation-v1.json");
    let backup = record.with_extension("previous.json");
    if record.exists() {
        std::fs::rename(&record, &backup).map_err(|_| failure("source backup unavailable"))?;
    }
    match runne_platform_desktop::publish_terminal_installation_source(
        root,
        &config_path,
        &cli,
        &daemon,
        &cli,
    ) {
        Ok(()) => inspect(),
        Err(_) => {
            if backup.exists() && !record.exists() {
                let _ = std::fs::rename(&backup, &record);
            }
            Err(failure("pinned installation source unavailable"))
        }
    }
}

/// Commits only the exact preview explicitly accepted by the local owner.
/// The manifest binds the fixed configuration and all three pinned executable images.
/// Callers must not invoke this automatically on connection failure or ordinary startup.
pub fn commit(expected_manifest: &str) -> Result<TerminalAdoptionPreview, DaemonError> {
    let (config, images, root) = verified_target()?;
    let manifest = hex::encode(images.manifest);
    if expected_manifest != manifest {
        return Err(failure(
            "adoption preview changed; obtain fresh owner consent",
        ));
    }
    // The existing bootstrap locks also exclude the old external runtime.
    let bootstrap = crate::bootstrap::bootstrap(&config)?;
    if !bootstrap.db_existed {
        return Err(failure("adoption cannot initialize an empty installation"));
    }
    images.revalidate().map_err(failure)?;
    let lineage = runne_store::schema::read_event_log_lineage_id(&bootstrap.db_conn)
        .map_err(|_| failure("adoption lineage unavailable"))?
        .ok_or_else(|| failure("adoption lineage missing"))?;
    let profile = super::first_activation::expected_profile(None)
        .map_err(|_| failure("adoption protected profile unavailable"))?;
    let stable = StableRuntimeBindingV1::new(
        bootstrap.local_session_authority_id,
        super::LOCAL_PRINCIPAL,
        *lineage.as_bytes(),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .map_err(|_| failure("adoption stable identity invalid"))?;
    // Persist the transition generation before its database transaction. A retry
    // reconstructs exactly that configuration, even after bootstrap advanced.
    let pending = journal::load_or_create(
        &root,
        &manifest,
        bootstrap.authority_id,
        bootstrap.local_session_authority_id,
        *lineage.as_bytes(),
        bootstrap.launch_generation,
    )?;
    images.revalidate().map_err(failure)?;
    crate::canonical_provider::adopt_terminal_provider(
        &config,
        bootstrap.authority_id,
        pending.generation,
        bootstrap.db_conn,
    )?;
    // The database commits first. Missing anchor means ordinary launch fails
    // closed; retrying this explicit operation finishes exact anchor publication.
    runne_platform_desktop::publish_terminal_installation_source(
        &root,
        &crate::config::external_config_path(),
        &images.cli,
        &images.daemon,
        &images.host,
    )
    .map_err(|_| failure("adoption committed; retry exact consent to bind source images"))?;
    runne_platform_desktop::publish_terminal_adoption_anchor(&root, &stable)
        .map_err(|_| failure("adoption committed; retry exact consent to publish anchor"))?;
    images.revalidate().map_err(failure)?;
    drop(bootstrap.locks);
    Ok(TerminalAdoptionPreview {
        runtime_root: root,
        manifest,
        already_adopted: true,
        provider_profile: config.provider_activation.binding().profile_id().to_owned(),
    })
}

fn verified_target() -> Result<(ConfigurationSnapshot, ImagePolicy, PathBuf), DaemonError> {
    let source = crate::config::load_verified_fixed_external_config()?;
    let config = source.snapshot().clone();
    if !config.provider_activation.requires_deepseek_execution()
        || config.secondary_profile_catalog.is_some()
        || config.linux_cli_credential_host.is_none()
    {
        return Err(failure(
            "adoption requires the existing standalone DeepSeek text installation",
        ));
    }
    let root = existing_root(&config)?;
    runne_platform_desktop::require_terminal_baseline_root(&root)
        .map_err(|_| failure("adoption runtime root is not owner-private"))?;
    let images = ImagePolicy::load(&config).map_err(failure)?;
    images.revalidate().map_err(failure)?;
    Ok((config, images, root))
}

fn existing_root(config: &ConfigurationSnapshot) -> Result<PathBuf, DaemonError> {
    let database = Path::new(&config.db_path);
    let root = database
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| failure("adoption runtime layout unavailable"))?;
    let canonical = root
        .canonicalize()
        .map_err(|_| failure("adoption root unavailable"))?;
    let defaults = BuiltInDefaults::new(&canonical);
    if database != Path::new(&defaults.db_path)
        || Path::new(&config.replay_integrity_key_path)
            != Path::new(&defaults.replay_integrity_key_path)
        || !database.is_file()
    {
        return Err(failure(
            "adoption requires the existing protected-compatible path layout",
        ));
    }
    Ok(canonical)
}

fn failure(message: &str) -> DaemonError {
    DaemonError::Bootstrap(message.to_owned())
}

fn adopted(config: &ConfigurationSnapshot, root: &Path) -> Result<bool, DaemonError> {
    let connection = runne_store::schema::open_existing_read_only(Path::new(&config.db_path))
        .map_err(|_| failure("adoption database unavailable"))?;
    adopted_connection(config, root, &connection)
}

fn adopted_connection(
    config: &ConfigurationSnapshot,
    root: &Path,
    connection: &rusqlite::Connection,
) -> Result<bool, DaemonError> {
    let lineage = runne_store::schema::read_event_log_lineage_id(connection)
        .map_err(|_| failure("adoption lineage unavailable"))?
        .ok_or_else(|| failure("adoption lineage missing"))?;
    let local = super::first_activation::read_owner_private_uuid(
        &Path::new(&config.replay_integrity_key_path).with_file_name("local-session-authority-id"),
    )
    .map_err(|_| failure("adoption local authority unavailable"))?;
    let profile = super::first_activation::expected_profile(None)
        .map_err(|_| failure("adoption profile unavailable"))?;
    let stable = StableRuntimeBindingV1::new(
        local,
        super::LOCAL_PRINCIPAL,
        *lineage.as_bytes(),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .map_err(|_| failure("adoption identity unavailable"))?;
    let anchor = runne_platform_desktop::terminal_adoption_anchor_matches(root, &stable)
        .map_err(|_| failure("adoption anchor conflicts"))?;
    let protected = connection.query_row(
        "SELECT activation_binding_kind='protected_v2' FROM provider_runtime_authority_state WHERE id=1",
        [], |row| row.get::<_, bool>(0),
    ).map_err(|_| failure("adoption authority unavailable"))?;
    Ok(anchor && protected)
}

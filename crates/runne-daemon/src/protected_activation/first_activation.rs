#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]

use super::*;

pub(super) fn expected_profile(
    enrollment_capability: Option<&super::launch::VerifiedProtectedEnrollmentCapability>,
) -> Result<ProtectedRuntimeProfileV1, LaunchAuthorityError> {
    let profile_hash: [u8; 32] = hex::decode(runne_runtime::bundle::PUBLISHED_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    ProtectedRuntimeProfileV1::new(
        runne_api::PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        runne_runtime::bundle::BUNDLE_ID,
        profile_hash,
        runne_http::runtime_profile::ordered_capability_digest(capabilities(enrollment_capability)),
    )
}

fn capabilities(
    enrollment_capability: Option<&super::launch::VerifiedProtectedEnrollmentCapability>,
) -> &'static [&'static str] {
    capabilities_for(
        enrollment_capability
            .is_some_and(super::launch::VerifiedProtectedEnrollmentCapability::is_qualified),
    )
}

const fn capabilities_for(qualified: bool) -> &'static [&'static str] {
    if qualified {
        runne_runtime::bundle::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
    } else {
        runne_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
    }
}

#[test]
fn v1_profile_without_a_sealed_capability_is_published() {
    let profile = expected_profile(None).unwrap();
    assert_eq!(
        profile.capability_digest(),
        &runne_http::runtime_profile::ordered_capability_digest(
            runne_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        )
    );
}

#[test]
fn sealed_enrollment_capability_selects_the_matching_profile_digest() {
    assert_eq!(
        capabilities_for(false),
        runne_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
    );
    assert_eq!(
        capabilities_for(true),
        runne_runtime::bundle::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
    );
}

pub(super) fn prepare_first_activation(
    request: &ProtectedLaunchRequestV1,
    runtime_root: &Path,
) -> Result<PendingFirstActivationV1, LaunchAuthorityError> {
    let authority_id = *uuid::Uuid::now_v7().as_bytes();
    let lineage_id = *uuid::Uuid::now_v7().as_bytes();
    let preparation_id = *uuid::Uuid::now_v7().as_bytes();
    let profile = request.profile().clone();
    let stable = StableRuntimeBindingV1::new(
        authority_id,
        request.principal_id(),
        lineage_id,
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )?;
    PendingFirstActivationV1::new(
        preparation_id,
        runtime_root_identity(runtime_root),
        stable,
        request.executable().clone(),
        profile,
    )
}

pub(super) fn verify_pending_request(
    request: &ProtectedLaunchRequestV1,
    pending: &PendingFirstActivationV1,
    runtime_root: &Path,
) -> Result<(), LaunchAuthorityError> {
    if pending.runtime_root_identity() != &runtime_root_identity(runtime_root)
        || pending.executable() != request.executable()
        || pending.profile() != request.profile()
        || pending.stable().principal_id() != request.principal_id()
    {
        return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
    }
    Ok(())
}

pub(super) fn preflight_existing(
    config: &ConfigurationSnapshot,
    expected: &StableRuntimeBindingV1,
    expected_preparation_id: Option<&[u8; 16]>,
    enrollment_capability: Option<&super::launch::VerifiedProtectedEnrollmentCapability>,
) -> Result<(), LaunchAuthorityError> {
    let profile = expected_profile(enrollment_capability)?;
    let db_path = Path::new(&config.db_path);
    if !db_path.exists() {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    match schema::open_existing_read_only(db_path) {
        Ok(connection) => validate_existing_connection(
            config,
            &connection,
            expected,
            expected_preparation_id,
            &profile,
        ),
        Err(_) => schema::with_protected_recovery_read_only_admission(db_path, |connection| {
            validate_existing_connection(
                config,
                connection,
                expected,
                expected_preparation_id,
                &profile,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding),
    }
}

pub(super) fn validate_existing_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    expected: &StableRuntimeBindingV1,
    expected_preparation_id: Option<&[u8; 16]>,
    expected_profile: &ProtectedRuntimeProfileV1,
) -> Result<(), LaunchAuthorityError> {
    let lineage = schema::read_event_log_lineage_id(connection)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?
        .ok_or(LaunchAuthorityError::MissingExpectedStableBinding)?;
    let preparation = schema::read_first_activation_preparation(connection)
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
    let local_authority_path =
        Path::new(&config.replay_integrity_key_path).with_file_name("local-session-authority-id");
    let local_authority = read_owner_private_uuid(&local_authority_path)?;
    if local_authority != *expected.authority_id()
        || lineage.as_bytes() != expected.lineage_id()
        || expected.principal_id() != LOCAL_PRINCIPAL
        || expected.profile_id() != expected_profile.profile_id()
        || expected.profile_hash() != expected_profile.profile_hash()
        || expected.capability_digest() != expected_profile.capability_digest()
        || expected_preparation_id
            .is_some_and(|expected_id| preparation.as_ref() != Some(expected_id))
    {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    Ok(())
}

include!("first_activation/resume.rs");
pub(super) fn validate_runtime_root(path: &Path) -> Result<PathBuf, LaunchAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    #[cfg(windows)]
    if !super::windows_acl::enforce_owner_acl(path) {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
    }
    std::fs::canonicalize(path).map_err(|_| LaunchAuthorityError::InvalidContract)
}

pub(super) fn read_owner_private_uuid(path: &Path) -> Result<[u8; 16], LaunchAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 16 {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    #[cfg(windows)]
    if !super::windows_acl::enforce_owner_acl(path) {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(LaunchAuthorityError::MissingExpectedStableBinding);
        }
    }
    let bytes: [u8; 16] = std::fs::read(path)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::MissingExpectedStableBinding)?;
    runne_domain::id::validate_uuid_v7_bytes(&bytes)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?;
    Ok(bytes)
}

#[cfg(unix)]
pub(super) fn runtime_root_identity(path: &Path) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;
    Sha256::digest(path.as_os_str().as_bytes()).into()
}

#[cfg(not(unix))]
pub(super) fn runtime_root_identity(path: &Path) -> [u8; 32] {
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

/// Generates non-zero control entropy without exposing it in diagnostics.
pub fn random_control_secret() -> [u8; 32] {
    let mut value = [0; 32];
    while value == [0; 32] {
        OsRng.fill_bytes(&mut value);
    }
    value
}

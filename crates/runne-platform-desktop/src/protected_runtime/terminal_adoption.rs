//! Exact anchor publication for the daemon-owned, explicit terminal adoption.
use super::{
    ACTIVATION_STATE_DIRECTORY, ActivationStateStore, LOCAL_PRINCIPAL, LaunchTestControls, Path,
    ProtectedBundledRuntimeError, StableRuntimeBindingV1, ensure_owner_private_directory,
    expected_profile_for_launch, require_linux_cli_baseline_root,
};

/// Publishes an existing runtime identity after the daemon committed adoption.
///
/// This writes no database state and grants no consent or enrollment authority.
/// The caller must retain exclusive runtime ownership through publication.
#[cfg(target_os = "linux")]
///
/// # Errors
/// Rejects invalid, conflicting, or unavailable owner-private activation state.
pub fn publish_terminal_adoption_anchor(
    root: &Path,
    stable: &StableRuntimeBindingV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    let root = ensure_owner_private_directory(root)?;
    let expected = expected_profile_for_launch(&root, true)?;
    if stable.principal_id() != LOCAL_PRINCIPAL
        || stable.profile_id() != expected.profile_id()
        || stable.profile_hash() != expected.profile_hash()
        || stable.capability_digest() != expected.capability_digest()
    {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    let store = ActivationStateStore::open(&root)?;
    if store.load_pending()?.is_some() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    store.persist_stable_exact(stable, &mut LaunchTestControls::production())
}

/// Reads an exact published anchor without creating activation state.
#[cfg(target_os = "linux")]
///
/// # Errors
/// Rejects invalid, conflicting, or unavailable owner-private activation state.
pub fn terminal_adoption_anchor_matches(
    root: &Path,
    expected: &StableRuntimeBindingV1,
) -> Result<bool, ProtectedBundledRuntimeError> {
    require_linux_cli_baseline_root(root)?;
    if !root.join(ACTIVATION_STATE_DIRECTORY).exists() {
        return Ok(false);
    }
    let store = ActivationStateStore::open(root)?;
    if store.load_pending()?.is_some() {
        return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
    }
    match store.load_stable()? {
        None => Ok(false),
        Some(actual) if &actual == expected => Ok(true),
        Some(_) => Err(ProtectedBundledRuntimeError::ActivationStateUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn anchor_publication_is_exact_and_does_not_replace_identity() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = directory.path().join("runtime");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = expected_profile_for_launch(&root, true).unwrap();
        let stable = StableRuntimeBindingV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            LOCAL_PRINCIPAL,
            *uuid::Uuid::now_v7().as_bytes(),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .unwrap();
        publish_terminal_adoption_anchor(&root, &stable).unwrap();
        publish_terminal_adoption_anchor(&root, &stable).unwrap();
        let changed = StableRuntimeBindingV1::new(
            *uuid::Uuid::now_v7().as_bytes(),
            LOCAL_PRINCIPAL,
            *stable.lineage_id(),
            profile.profile_id(),
            *profile.profile_hash(),
            *profile.capability_digest(),
        )
        .unwrap();
        assert!(publish_terminal_adoption_anchor(&root, &changed).is_err());
        assert_eq!(
            ActivationStateStore::open(&root)
                .unwrap()
                .load_stable()
                .unwrap(),
            Some(stable)
        );
    }
}

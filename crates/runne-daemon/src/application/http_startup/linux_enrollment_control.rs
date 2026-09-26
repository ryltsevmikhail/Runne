use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use crate::canonical_provider::readiness::native_credential_access_policy;
use crate::error::DaemonError;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_provider::CredentialEnrollmentAuthorityPair;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_secure_store::NativeProviderCredentialReaders;
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

pub(super) fn runtime_config(max_in_flight: u32) -> Result<super::RuntimeConfig, DaemonError> {
    Ok(super::RuntimeConfig {
        max_in_flight_requests: usize::try_from(max_in_flight).map_err(|_| {
            DaemonError::Config("max_in_flight does not fit this platform".to_owned())
        })?,
        ..super::RuntimeConfig::default()
    })
}

pub(super) fn compose_startup_enrollment(
    config: &super::ConfigurationSnapshot,
    runtime_authority: [u8; 16],
    replay_lineage: runne_domain::id::EventLogLineageId,
    provider_service: Option<&Arc<crate::canonical_provider::DaemonCanonicalProviderService>>,
    protected: bool,
    root_admission_keys: Option<&runne_api::ProtectedActivationKeys>,
    capability: Option<&crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
) -> Result<super::enrollment::EnrollmentHttpComposition, DaemonError> {
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    let candidate = protected && has_installed_candidate(&config.db_path);
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    let control = control_or_compose(
        candidate,
        provider_service.and_then(|service| service.credential_enrollment_control()),
        || {
            let connection = super::super::open_runtime_connection(
                &config.db_path,
                runne_store::schema::ConnectionMode::ValidatedReopen,
                runtime_authority,
                replay_lineage,
                "protected enrollment credential store",
            )?;
            compose(connection, runtime_authority)
        },
    )?;
    #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
    let _ = (config, runtime_authority, replay_lineage);
    #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
    let control = provider_service.and_then(|service| service.credential_enrollment_control());
    super::enrollment::compose(
        provider_service,
        control,
        protected,
        root_admission_keys,
        capability,
    )
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn has_installed_candidate(db_path: &str) -> bool {
    let Some(runtime_root) = std::path::Path::new(db_path)
        .parent()
        .and_then(std::path::Path::parent)
    else {
        return false;
    };
    let updates = runtime_root.join("updates");
    std::fs::symlink_metadata(&updates)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        && has_numbered_journal(&updates, "install-state.json")
        && has_numbered_journal(&updates, "trust-state.json")
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn has_numbered_journal(updates: &std::path::Path, base: &str) -> bool {
    const MAX_CANDIDATE_ENTRIES: usize = 512;
    let prefix = format!("{base}.");
    let Ok(entries) = std::fs::read_dir(updates) else {
        return false;
    };
    entries
        .take(MAX_CANDIDATE_ENTRIES)
        .filter_map(Result::ok)
        .any(|entry| {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return false;
            };
            let Some(sequence) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".json"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                return false;
            };
            sequence > 0
                && std::fs::symlink_metadata(entry.path())
                    .is_ok_and(|metadata| metadata.file_type().is_file())
        })
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn control_or_compose<T>(
    protected: bool,
    existing: Option<T>,
    compose: impl FnOnce() -> Result<T, DaemonError>,
) -> Result<Option<T>, DaemonError> {
    match existing {
        Some(control) => Ok(Some(control)),
        None if protected => compose().map(Some),
        None => Ok(None),
    }
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(super) fn compose(
    connection: runne_store::schema::ManagedConnection,
    runtime_authority: [u8; 16],
) -> Result<Arc<DaemonProviderCredentialEnrollmentControl>, DaemonError> {
    let access = native_credential_access_policy()?;
    let (lifecycle_authority, readback, _dispatch, _) =
        NativeProviderCredentialReaders::new(access).into_parts();
    let (enrollment_store_authority, measurements) =
        CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection,
        lifecycle_authority,
        enrollment_store_authority.clone(),
    )
    .map_err(|_| DaemonError::Bootstrap("provider credential lifecycle unavailable".into()))?;
    DaemonProviderCredentialEnrollmentControl::new(
        Arc::new(store),
        readback,
        measurements,
        enrollment_store_authority,
        runtime_authority,
        1,
    )
    .map(Arc::new)
    .map_err(|_| DaemonError::Bootstrap("provider credential control unavailable".into()))
}

#[cfg(all(test, target_os = "linux", feature = "desktop-protected"))]
mod tests {
    use super::{control_or_compose, has_installed_candidate};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn protected_without_provider_control_composes_once() {
        let calls = AtomicUsize::new(0);
        let selected = control_or_compose(true, None, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            selected
                .as_deref()
                .is_some_and(|value| *value == "standalone")
        );
    }

    #[test]
    fn existing_provider_control_is_reused_without_composition() {
        let calls = AtomicUsize::new(0);
        let existing = Arc::new("provider");
        let selected = control_or_compose(true, Some(Arc::clone(&existing)), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
        })
        .unwrap()
        .unwrap();
        assert!(Arc::ptr_eq(&selected, &existing));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unprotected_startup_does_not_compose_a_control() {
        let calls = AtomicUsize::new(0);
        let selected = control_or_compose(false, None, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
        })
        .unwrap();
        assert!(selected.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn candidate_requires_both_regular_installed_journals() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = temporary.path();
        let runtime_root = profile.join("bundled-runtime");
        let db_path = runtime_root.join("runne-daemon/event-log.db");
        std::fs::create_dir_all(runtime_root.join("updates")).unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::write(
            runtime_root.join("updates/install-state.json.1.json"),
            b"candidate",
        )
        .unwrap();
        std::fs::write(
            runtime_root.join("updates/trust-state.json.1.json"),
            b"candidate",
        )
        .unwrap();
        assert!(has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::remove_file(runtime_root.join("updates/trust-state.json.1.json")).unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
        std::fs::remove_file(runtime_root.join("updates/install-state.json.1.json")).unwrap();
        let wrong_parent = profile.join("updates");
        std::fs::create_dir_all(&wrong_parent).unwrap();
        std::fs::write(
            wrong_parent.join("install-state.json.1.json"),
            b"wrong parent",
        )
        .unwrap();
        std::fs::write(
            wrong_parent.join("trust-state.json.1.json"),
            b"wrong parent",
        )
        .unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
    }

    #[test]
    fn unsuffixed_and_temporary_journals_are_not_installed_candidates() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_root = temporary.path().join("bundled-runtime");
        let db_path = runtime_root.join("runne-daemon/event-log.db");
        let updates = runtime_root.join("updates");
        std::fs::create_dir_all(&updates).unwrap();
        std::fs::write(updates.join("install-state.json"), b"legacy").unwrap();
        std::fs::write(updates.join("trust-state.json"), b"legacy").unwrap();
        std::fs::write(updates.join("install-state.json.1.tmp"), b"partial").unwrap();
        std::fs::write(updates.join("trust-state.json.1.tmp"), b"partial").unwrap();
        assert!(!has_installed_candidate(db_path.to_str().unwrap()));
    }
}

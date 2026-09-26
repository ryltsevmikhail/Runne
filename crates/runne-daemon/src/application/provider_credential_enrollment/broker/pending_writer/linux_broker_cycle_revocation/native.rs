use super::fixture::DurableFixture;
use runne_provider::{CredentialDispatchCapability, CredentialVersionRef};
use runne_secure_store::{
    NativeKeyringStore, NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialStatus, SecureStoreError,
};
use std::process::Command;

pub(super) fn reconcile_native(f: &DurableFixture, binary: &std::path::Path, now: i64) {
    let access = runne_secure_store::ProviderCredentialAccessPolicy::new(
        binary,
        &std::env::current_exe().unwrap(),
    )
    .unwrap();
    let (_, reader, _, _) =
        runne_secure_store::NativeProviderCredentialReaders::new(access).into_parts();
    let gateway = crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway::new(f.store(), reader.as_ref());
    gateway.reconcile_online(now).unwrap();
}

pub(super) fn item_service(version: &CredentialVersionRef) -> String {
    let digest: String = version
        .ref_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{}.version.{}.{}",
        runne_secure_store::PROVIDER_CREDENTIAL_SERVICE,
        version.version(),
        digest
    )
}

pub(super) struct NativeItemCleanup(String);

impl NativeItemCleanup {
    pub(super) fn new(service: &str) -> Self {
        Self(service.to_owned())
    }
}

impl Drop for NativeItemCleanup {
    fn drop(&mut self) {
        clear_item(&self.0);
    }
}

fn clear_item(service: &str) {
    let _ = Command::new("secret-tool")
        .args([
            "clear", "service", service, "username", "openai", "target", "default",
        ])
        .status();
    let description = format!("keyring-rs:openai@{service}");
    if let Ok(found) = Command::new("keyctl")
        .args(["search", "@s", "user", &description])
        .output()
        && found.status.success()
        && let Ok(serial) = String::from_utf8(found.stdout)
    {
        let _ = Command::new("keyctl")
            .args(["invalidate", serial.trim()])
            .status();
    }
}

pub(super) fn poll_absence(service: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let found = Command::new("secret-tool")
            .args([
                "search", "service", service, "username", "openai", "target", "default",
            ])
            .output()
            .unwrap();
        let cached = Command::new("keyctl")
            .args([
                "search",
                "@s",
                "user",
                &format!("keyring-rs:openai@{service}"),
            ])
            .output()
            .unwrap();
        if found.status.success() && found.stdout.is_empty() && !cached.status.success() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "native version remains after Revoke"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub(super) fn assert_native_absent(service: &str) {
    poll_absence(service);
}

pub(super) fn assert_version_missing(binary: &std::path::Path, version: &CredentialVersionRef) {
    let access =
        ProviderCredentialAccessPolicy::new(binary, &std::env::current_exe().unwrap()).unwrap();
    let native = NativeKeyringStore::new();
    assert_eq!(
        native.version_status(version, &access).unwrap(),
        ProviderCredentialStatus::Missing,
        "the unique allocated native version must be absent before Pair"
    );
}

pub(super) fn load_sqlite_leased_native_secret(
    f: &DurableFixture,
    binary: &std::path::Path,
) -> CredentialDispatchCapability {
    let lease = f
        .store()
        .active_lease(f.operation.provider())
        .unwrap()
        .expect("paired SQLite version must have an active lease");
    let capability = f.lifecycle.issue_dispatch(lease);
    let access =
        ProviderCredentialAccessPolicy::new(binary, &std::env::current_exe().unwrap()).unwrap();
    let native = NativeKeyringStore::new_versioned(f.native_authority.clone());
    let material = native.load_version(&capability, &access).unwrap();
    assert!(material.with_bytes(|bytes| bytes == b"d1.1b-disposable-pair-seed"));
    capability
}

pub(super) fn assert_old_native_capability_cannot_load(
    f: &DurableFixture,
    binary: &std::path::Path,
    capability: &CredentialDispatchCapability,
) {
    let access =
        ProviderCredentialAccessPolicy::new(binary, &std::env::current_exe().unwrap()).unwrap();
    let native = NativeKeyringStore::new_versioned(f.native_authority.clone());
    assert!(matches!(
        native.load_version(capability, &access),
        Err(SecureStoreError::ProviderCredentialNotFound)
    ));
}

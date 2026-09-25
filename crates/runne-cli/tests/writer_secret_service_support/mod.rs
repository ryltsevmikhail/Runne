use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
use runne_secure_store::PROVIDER_CREDENTIAL_SERVICE;
use std::fmt::Write as _;
use std::process::Command;

pub struct ExactItemCleanup {
    service: String,
}

impl ExactItemCleanup {
    pub fn for_version(version: u64) -> (Self, String) {
        let reference = runne_provider::CredentialVersionRef::new(
            runne_provider::ProviderId::new("openai").unwrap(),
            version,
        )
        .unwrap();
        let mut digest = String::with_capacity(64);
        for byte in reference.ref_digest() {
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        let service = format!("{PROVIDER_CREDENTIAL_SERVICE}.version.{version}.{digest}");
        (
            Self {
                service: service.clone(),
            },
            service,
        )
    }
}

impl Drop for ExactItemCleanup {
    fn drop(&mut self) {
        let _ = clear_item(&self.service);
        let _ = clear_cache_item(&self.service);
    }
}

pub struct Child(pub runne_platform_desktop::provider_credential_broker::UnixRetainedWriterProcess);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.terminate_retained_child();
        let _ = self.0.reap_retained_child();
    }
}

pub fn clear_item(service: &str) -> Result<(), ()> {
    if !search_item(service)?.is_empty() {
        let cleared = Command::new("secret-tool")
            .args([
                "clear", "service", service, "username", "openai", "target", "default",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| ())?;
        if !cleared.success() {
            return Err(());
        }
    }
    search_item(service)?.is_empty().then_some(()).ok_or(())
}

pub fn search_item(service: &str) -> Result<Vec<u8>, ()> {
    let result = Command::new("secret-tool")
        .args([
            "search", "service", service, "username", "openai", "target", "default",
        ])
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| ())?;
    result.status.success().then_some(result.stdout).ok_or(())
}

pub fn clear_cache_item(service: &str) -> Result<(), ()> {
    let description = format!("keyring-rs:openai@{service}");
    let result = Command::new("keyctl")
        .args(["search", "@s", "user", &description])
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| ())?;
    if result.status.success() {
        let serial = String::from_utf8(result.stdout).map_err(|_| ())?;
        let invalidated = Command::new("keyctl")
            .args(["invalidate", serial.trim()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| ())?;
        if !invalidated.success() {
            return Err(());
        }
    }
    let remains = Command::new("keyctl")
        .args(["search", "@s", "user", &description])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| ())?;
    (!remains.success()).then_some(()).ok_or(())
}

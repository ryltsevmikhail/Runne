//! Desktop preprompt Linux activation gate (default OFF).
//!
//! The desktop independently denies every enrollment intent outside the
//! explicit activation scope (legacy V1 `DeepSeek` or V2 closed catalog), or whose
//! approval record does not bind to this exact installation and host —
//! BEFORE any prompt, lease, or store mutation. The gate shares the record
//! format and facts canonicalizer with the daemon preadmission gate
//! (`runne-api linux_activation_policy`), but each side derives its context
//! from its own REAL managed runtime state: the desktop context is installed
//! once at startup as a weak reference to the managed supervisor. Each check
//! measures its live protected daemon and staged writer and reads authority
//! from the verified readiness transcript. Missing context denies closed.

use std::sync::{Arc, OnceLock, Weak};

use runne_api::ProviderCredentialProviderV2;
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    ACTIVATION_RECORD_FILE, LinuxEnrollmentActivationRecord, LinuxEnrollmentDecision,
    LinuxEnrollmentProvider, LinuxInstallationFacts, evaluate_linux_enrollment,
};

use super::CredentialIntentIpc;
use crate::bundled_runtime::BundledRuntimeController;

type ManagedLinuxContext = Weak<BundledRuntimeController>;
static MANAGED_CONTEXT: OnceLock<ManagedLinuxContext> = OnceLock::new();

/// Retains no independent authority or path guesses. Every check asks the
/// managed supervisor for facts of its currently retained protected process.
pub fn install_managed_context(controller: &Arc<BundledRuntimeController>) {
    let _ = MANAGED_CONTEXT.set(Arc::downgrade(controller));
}

pub(super) struct DesktopLinuxActivationGate {
    record: Option<LinuxEnrollmentActivationRecord>,
    facts: LinuxInstallationFacts,
}

impl DesktopLinuxActivationGate {
    #[must_use]
    pub(super) const fn from_parts(
        record: Option<LinuxEnrollmentActivationRecord>,
        facts: LinuxInstallationFacts,
    ) -> Self {
        Self { record, facts }
    }

    #[must_use]
    fn from_managed(context: &ManagedLinuxContext) -> Option<Self> {
        let (runtime_root, facts) = context.upgrade()?.linux_activation_context()?;
        let record = read_approval_record(&runtime_root.join(ACTIVATION_RECORD_FILE));
        Some(Self::from_parts(record, facts))
    }

    fn enforce(&self, provider: ProviderCredentialProviderV2) -> Result<(), &'static str> {
        match evaluate_linux_enrollment(
            self.record.as_ref(),
            &self.facts,
            LinuxEnrollmentProvider::from_id(provider.as_str()),
        ) {
            LinuxEnrollmentDecision::Allowed => Ok(()),
            LinuxEnrollmentDecision::Denied(_) => Err("provider_credential_unsupported"),
        }
    }
}

/// Reads the approval record with a symlink-rejecting, fd-verified open.
///
/// The record is non-secret, but tampering must fail closed: any symlinked
/// path component resolves to a different canonical path and is rejected
/// before opening, and every permission/ownership check reads the metadata
/// of the OPEN descriptor. (The daemon side uses its established
/// `O_NOFOLLOW` loader; this crate has no such primitive without new deps,
/// so canonical-path equality plus fd checks provide the same closed
/// behavior under the accepted TD-1 same-UID trust envelope.)
fn read_approval_record(path: &std::path::Path) -> Option<LinuxEnrollmentActivationRecord> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    let canonical = std::fs::canonicalize(path).ok()?;
    if canonical != path {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 4096
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != std::fs::metadata("/proc/self").ok()?.uid()
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    LinuxEnrollmentActivationRecord::from_config_json(std::str::from_utf8(&bytes).ok()?)
}

/// The real preprompt entry called by credential dispatch on Linux before
/// any lease, prompt, or store mutation. Denies closed without an installed
/// managed context and for every provider outside the allowlist.
#[cfg(target_os = "linux")]
pub(super) fn enforce_pre_prompt_gate(request: &CredentialIntentIpc) -> Result<(), &'static str> {
    if !request.supported_enrollment_action() {
        return Ok(());
    }
    match MANAGED_CONTEXT.get() {
        Some(context) => DesktopLinuxActivationGate::from_managed(context)
            .ok_or("provider_credential_unsupported")?
            .enforce(request.provider),
        None => Err("provider_credential_unsupported"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> LinuxEnrollmentActivationRecord {
        LinuxEnrollmentActivationRecord {
            provider_scope: runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentScope::LegacyDeepSeek,
            runtime_root_digest: [1; 32],
            desktop_image_digest: [2; 32],
            writer_image_digest: [3; 32],
            daemon_image_digest: [4; 32],
            runtime_authority_id: [5; 16],
            machine_id_digest: [6; 32],
            approved_at_unix_millis: 1,
        }
    }

    fn facts() -> LinuxInstallationFacts {
        LinuxInstallationFacts {
            runtime_root_digest: [1; 32],
            desktop_image_digest: [2; 32],
            writer_image_digest: [3; 32],
            daemon_image_digest: [4; 32],
            runtime_authority_id: [5; 16],
            machine_id_digest: [6; 32],
        }
    }

    #[test]
    fn approved_fixture_allows_deepseek_and_denies_everything_else() {
        let gate = DesktopLinuxActivationGate::from_parts(Some(record()), facts());
        assert_eq!(gate.enforce(ProviderCredentialProviderV2::DeepSeek), Ok(()));
        assert_eq!(
            gate.enforce(ProviderCredentialProviderV2::OpenAi),
            Err("provider_credential_unsupported")
        );
    }

    #[test]
    fn missing_or_wrong_root_copy_denies_deepseek() {
        let off = DesktopLinuxActivationGate::from_parts(None, facts());
        assert_eq!(
            off.enforce(ProviderCredentialProviderV2::DeepSeek),
            Err("provider_credential_unsupported")
        );
        let copied = DesktopLinuxActivationGate::from_parts(
            Some(record()),
            LinuxInstallationFacts {
                runtime_root_digest: [9; 32],
                ..facts()
            },
        );
        assert_eq!(
            copied.enforce(ProviderCredentialProviderV2::DeepSeek),
            Err("provider_credential_unsupported")
        );
    }

    #[test]
    fn same_record_passes_both_desktop_and_daemon_style_evaluation() {
        // Cross-boundary fixture: the SAME approved record/facts pair must be
        // allowed by the shared evaluation used by BOTH gates, while a record
        // copied to a different runtime root is denied on either side.
        assert_eq!(
            evaluate_linux_enrollment(
                Some(&record()),
                &facts(),
                LinuxEnrollmentProvider::from_id("deepseek")
            ),
            LinuxEnrollmentDecision::Allowed
        );
        assert_eq!(
            evaluate_linux_enrollment(
                Some(&record()),
                &LinuxInstallationFacts {
                    runtime_root_digest: [9; 32],
                    ..facts()
                },
                LinuxEnrollmentProvider::from_id("deepseek")
            ),
            LinuxEnrollmentDecision::Denied(
                runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentDenial::InstallationMismatch
            )
        );
    }

    #[test]
    fn approval_reader_rejects_symlinks_and_loose_permissions() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("fixture dir");
        let real = dir.path().join("activation.json");
        let mut file = std::fs::File::create(&real).expect("create");
        file.write_all(record().to_config_json().as_bytes())
            .expect("write");
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions).unwrap();
        drop(file);
        let canonical = std::fs::canonicalize(&real).unwrap();
        assert_eq!(canonical, real);
        let linked = dir.path().join("linked.json");
        std::os::unix::fs::symlink(&real, &linked).expect("symlink");
        assert!(read_approval_record(&linked).is_none());
    }
}

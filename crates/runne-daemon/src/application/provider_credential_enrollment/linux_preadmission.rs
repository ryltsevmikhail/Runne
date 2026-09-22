//! Daemon preadmission Linux activation gate (default OFF).
//!
//! The daemon independently denies every enrollment admission outside the
//! explicit activation scope (legacy V1 DeepSeek or V2 closed catalog),
//! or whose activation record does not bind to this exact installation and
//! host, BEFORE any broker transfer or writer spawn. The record lives in the
//! managed runtime root; live authority and image measurements come from the
//! protected transition. Approval is read-only and never a source of authority.

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_api::ProviderCredentialProviderV2;
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    ACTIVATION_RECORD_FILE, LinuxEnrollmentActivationRecord, LinuxEnrollmentProvider,
    LinuxInstallationFacts, evaluate_linux_enrollment,
};

/// Secure loader for the approval record mirroring the existing sidecar
/// pattern: `O_NOFOLLOW` open (`crate::lock::O_NOFOLLOW_VAL`), then every
/// check reads the OPEN descriptor's metadata; any deviation denies closed.
pub(crate) fn load_activation_record(
    path: &std::path::Path,
) -> Option<LinuxEnrollmentActivationRecord> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if path.canonicalize().ok()?.as_path() != path {
        return None;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::lock::O_NOFOLLOW_VAL | 0o4000) // Linux O_NONBLOCK
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    let readable = metadata.is_file()
        && metadata.len() > 0
        && metadata.len() <= 4096
        && metadata.mode() & 0o077 == 0
        && metadata.uid() == std::fs::metadata("/proc/self").ok()?.uid();
    if !readable {
        return None;
    }
    let mut bytes = Vec::new();
    (&mut file).take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    LinuxEnrollmentActivationRecord::from_config_json(std::str::from_utf8(&bytes).ok()?)
}

#[derive(Clone)]
pub(crate) struct DaemonLinuxPreadmission {
    record: Option<LinuxEnrollmentActivationRecord>,
    record_path: Option<std::path::PathBuf>,
    facts: LinuxInstallationFacts,
}

impl DaemonLinuxPreadmission {
    /// Builds the gate from injected facts and an already-loaded record.
    #[must_use]
    pub(crate) const fn from_parts(
        record: Option<LinuxEnrollmentActivationRecord>,
        facts: LinuxInstallationFacts,
    ) -> Self {
        Self {
            record,
            record_path: None,
            facts,
        }
    }

    /// Uses facts independently measured from the authenticated protected peer.
    /// The approval record never supplies runtime authority or layout paths.
    pub(crate) fn from_managed(
        runtime_root: &std::path::Path,
        facts: LinuxInstallationFacts,
    ) -> Self {
        Self {
            record: None,
            record_path: Some(runtime_root.join(ACTIVATION_RECORD_FILE)),
            facts,
        }
    }

    pub(crate) fn disabled() -> Self {
        Self::from_parts(None, Self::zero_facts())
    }

    fn zero_facts() -> LinuxInstallationFacts {
        LinuxInstallationFacts {
            runtime_root_digest: [0; 32],
            desktop_image_digest: [0; 32],
            writer_image_digest: [0; 32],
            daemon_image_digest: [0; 32],
            runtime_authority_id: [0; 16],
            machine_id_digest: [0; 32],
        }
    }

    /// Denies closed (`provider_credential_unsupported`) unless the policy
    /// allows this provider for this exact installation.
    pub(crate) fn enforce(
        &self,
        provider: ProviderCredentialProviderV2,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        // A retained session must not retain an approval removed by the owner.
        let record = match self.record_path.as_deref() {
            Some(path) => load_activation_record(path),
            None => self.record,
        };
        match evaluate_linux_enrollment(
            record.as_ref(),
            &self.facts,
            LinuxEnrollmentProvider::from_id(provider.as_str()),
        ) {
            runne_api::provider_credential_enrollment::linux_activation_policy::LinuxEnrollmentDecision::Allowed => Ok(()),
            _ => Err(ProviderCredentialEnrollmentHostError::Unsupported),
        }
    }
}

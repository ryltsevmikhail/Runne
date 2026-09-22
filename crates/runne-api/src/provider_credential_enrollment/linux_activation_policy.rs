//! Shared Linux enrollment activation policy (typed, default OFF).
//!
//! DESIGN v6 §4-P5/§6-F6: the Linux protected enrollment path stays disabled
//! on every host until one explicit, non-secret activation record exists
//! inside the protected runtime-root config boundary, written only by a
//! separate owner live-setup. Historical V1 records retain DeepSeek-only scope;
//! explicit V2 records cover the closed provider catalog. Both bind to this
//! installation and host (runtime-root digest,
//! desktop/writer/daemon image digests, runtime authority id, machine-id
//! digest recorded at activation). Both real entry points — desktop dispatch
//! before any prompt, daemon admission before broker transfer/spawn —
//! evaluate this policy fail-closed. This is an internal typed policy
//! document, not part of the public wire contract.

use super::ProviderCredentialProviderV2;

#[path = "linux_activation_record_codec.rs"]
mod codec;

/// Closed provider identity shared with the protected enrollment catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxEnrollmentProvider(ProviderCredentialProviderV2);

impl LinuxEnrollmentProvider {
    pub const DEEP_SEEK: Self = Self(ProviderCredentialProviderV2::DeepSeek);

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0.as_str()
    }

    /// Unknown identifiers never acquire an enrollment identity.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        id.parse().ok().map(Self)
    }
}

/// Explicit record scope; historical records never acquire broader authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxEnrollmentScope {
    LegacyDeepSeek,
    Catalog,
}

/// TD-1 approval marker recorded inside every approved activation record.
pub const TD1_APPROVAL_MARKER: &str = "td1-2026-09-21-limited-deepseek-bigpc-user-keyring";

/// One approved activation record (all fields are non-secret digests/ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxEnrollmentActivationRecord {
    pub provider_scope: LinuxEnrollmentScope,
    pub runtime_root_digest: [u8; 32],
    pub desktop_image_digest: [u8; 32],
    pub writer_image_digest: [u8; 32],
    pub daemon_image_digest: [u8; 32],
    pub runtime_authority_id: [u8; 16],
    pub machine_id_digest: [u8; 32],
    pub approved_at_unix_millis: u64,
}

/// Current installation/host facts supplied by the enforcing process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxInstallationFacts {
    pub runtime_root_digest: [u8; 32],
    pub desktop_image_digest: [u8; 32],
    pub writer_image_digest: [u8; 32],
    pub daemon_image_digest: [u8; 32],
    pub runtime_authority_id: [u8; 16],
    pub machine_id_digest: [u8; 32],
}

/// Why the activation policy denied one enrollment intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxEnrollmentDenial {
    PolicyAbsent,
    ProviderNotAllowed,
    InstallationMismatch,
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxEnrollmentDecision {
    Allowed,
    Denied(LinuxEnrollmentDenial),
}

/// Evaluates one enrollment intent against the activation policy.
#[must_use]
pub fn evaluate_linux_enrollment(
    record: Option<&LinuxEnrollmentActivationRecord>,
    facts: &LinuxInstallationFacts,
    provider: Option<LinuxEnrollmentProvider>,
) -> LinuxEnrollmentDecision {
    let Some(provider) = provider else {
        return LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::ProviderNotAllowed);
    };
    let Some(record) = record else {
        return LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::PolicyAbsent);
    };
    if record.provider_scope == LinuxEnrollmentScope::LegacyDeepSeek
        && provider != LinuxEnrollmentProvider::DEEP_SEEK
    {
        return LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::ProviderNotAllowed);
    }
    let bound = record.runtime_root_digest == facts.runtime_root_digest
        && record.desktop_image_digest == facts.desktop_image_digest
        && record.writer_image_digest == facts.writer_image_digest
        && record.daemon_image_digest == facts.daemon_image_digest
        && record.runtime_authority_id == facts.runtime_authority_id
        && record.machine_id_digest == facts.machine_id_digest
        && record.approved_at_unix_millis > 0;
    if bound {
        LinuxEnrollmentDecision::Allowed
    } else {
        LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::InstallationMismatch)
    }
}

/// Canonical installation layout shared by BOTH enforcement sites.
///
/// The authority id is the LIVE existing `local-session-authority-id`
/// sidecar (16-byte owner UUID written by first activation) — never a
/// parallel trust root. The approval record is the only new non-secret
/// file and it binds against the live authority, root, images, and host.
pub struct LinuxInstallationLayout<'a> {
    pub runtime_root: &'a std::path::Path,
    pub desktop_image: &'a std::path::Path,
    pub writer_image: &'a std::path::Path,
    pub daemon_image: &'a std::path::Path,
    pub machine_id_path: &'a std::path::Path,
}

pub const ACTIVATION_RECORD_FILE: &str = "linux-enrollment-activation.json";
pub const AUTHORITY_SIDECAR_FILE: &str = "local-session-authority-id";

impl LinuxInstallationLayout<'_> {
    /// Computes the full installation facts for this layout; the LIVE
    /// authority id is supplied by the caller from the existing protected
    /// sidecar through its established secure loader.
    #[must_use]
    pub fn canonicalize_facts(
        &self,
        live_authority_id: [u8; 16],
    ) -> Option<LinuxInstallationFacts> {
        if live_authority_id == [0; 16] {
            return None;
        }
        let root = self.runtime_root.canonicalize().ok()?;
        if !root.is_dir() {
            return None;
        }
        Some(LinuxInstallationFacts {
            runtime_root_digest: digest_of_path_string(&root),
            desktop_image_digest: file_digest(self.desktop_image)?,
            writer_image_digest: file_digest(self.writer_image)?,
            daemon_image_digest: file_digest(self.daemon_image)?,
            runtime_authority_id: live_authority_id,
            machine_id_digest: file_digest(self.machine_id_path)?,
        })
    }
}

fn digest_of_path_string(path: &std::path::Path) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

fn file_digest(path: &std::path::Path) -> Option<[u8; 32]> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Linux O_NONBLOCK: opening a substituted FIFO must not hang admission.
        options.custom_flags(0o4000);
    }
    let mut file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0; 8192];
    let mut read_bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        read_bytes = read_bytes.checked_add(count as u64)?;
        hasher.update(&buffer[..count]);
    }
    if read_bytes != metadata.len() || file.metadata().ok()?.len() != read_bytes {
        return None;
    }
    Some(hasher.finalize().into())
}

#[cfg(test)]
#[path = "linux_activation_policy_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "linux_catalog_scope_tests.rs"]
mod catalog_scope_tests;

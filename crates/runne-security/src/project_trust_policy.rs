//! Single policy authority for T1 source admission (frozen inventory §F/S2).
//!
//! Stage 1 `admit_source` decides on metadata only, before any content is
//! read. Stage 2 byte inspection stays on the existing prohibited-content
//! boundary and is exposed through the same authority so callers observe one
//! authority and one epoch. Authority errors are fail-closed.

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::project_trust::{
    FROZEN_POLICY_VERSION, ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus, SourceAdmission, SourceAdmissionRequest, SourceChannel, SourceDenyReason,
    TrustAdmissionError,
};
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;

/// Path components rejected before deny comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    /// Absolute path or rooted component.
    Absolute,
    /// Parent traversal component.
    ParentTraversal,
    /// Home shorthand or shell-ish prefix.
    HomePrefix,
    /// Empty component (double separator or trailing separator).
    EmptyComponent,
    /// Backslash is ambiguous across platforms.
    Backslash,
    /// Control characters are never legitimate in a source path.
    ControlCharacter,
    /// Reserved characters rejected cross-platform (F5: Windows drive
    /// letters and NTFS ADS colons are unsupported path forms).
    ReservedCharacter,
}

/// Frozen component deny set (inventory §G3): exact component matches.
pub const FROZEN_DENY_COMPONENTS: [&str; 8] = [
    ".git",
    ".ssh",
    ".aws",
    ".env",
    ".netrc",
    ".npmrc",
    "id_rsa",
    "credentials.json",
];

/// Frozen suffix deny set (inventory §G3).
pub const FROZEN_DENY_SUFFIXES: [&str; 5] = [".key", ".pem", ".p12", ".ppk", ".gpg"];

/// NFC-normalizes and validates a workspace-relative path.
///
/// Returns the normalized components. Ambiguous and unsupported shapes are
/// rejected, never repaired: absolute paths, `..`, `~`, backslashes, empty
/// components, control characters and reserved `:` all fail closed.
pub fn normalize_source_path(raw: &str) -> Result<Vec<String>, PathRejection> {
    if raw.starts_with('/') {
        return Err(PathRejection::Absolute);
    }
    if raw.contains('\\') {
        return Err(PathRejection::Backslash);
    }
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(PathRejection::ControlCharacter);
    }
    if raw.is_empty() {
        return Err(PathRejection::EmptyComponent);
    }
    let mut components = Vec::new();
    for component in raw.split('/') {
        if component.is_empty() {
            return Err(PathRejection::EmptyComponent);
        }
        if component == "." {
            return Err(PathRejection::EmptyComponent);
        }
        if component == ".." {
            return Err(PathRejection::ParentTraversal);
        }
        if component.starts_with('~') {
            return Err(PathRejection::HomePrefix);
        }
        if component.contains(':') {
            return Err(PathRejection::ReservedCharacter);
        }
        let normalized: String = component.nfc().collect();
        if normalized.starts_with('/') {
            return Err(PathRejection::Absolute);
        }
        components.push(normalized);
    }
    Ok(components)
}

/// ASCII case-insensitive byte equality (deny names are all-ASCII).
fn ascii_case_fold_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .map(u8::to_ascii_lowercase)
            .zip(right.iter().map(u8::to_ascii_lowercase))
            .all(|(a, b)| a == b)
}

/// Whether normalized components match the frozen deny set (§G3).
pub fn denied_by_frozen_set(components: &[String]) -> bool {
    components.iter().any(|component| {
        let bytes = component.as_bytes();
        FROZEN_DENY_COMPONENTS
            .iter()
            .any(|denied| ascii_case_fold_bytes(bytes, denied.as_bytes()))
            || FROZEN_DENY_SUFFIXES.iter().any(|suffix| {
                let suffix = suffix.as_bytes();
                suffix.len() <= bytes.len()
                    && ascii_case_fold_bytes(&bytes[bytes.len() - suffix.len()..], suffix)
            })
    })
}

/// One policy authority owning both admission stages for a process.
pub struct ProjectTrustPolicyAuthority {
    persistence: Arc<dyn ProjectTrustPersistence>,
    byte_inspection: Option<Arc<dyn ProhibitedContentPort>>,
}

impl ProjectTrustPolicyAuthority {
    /// Builds the authority over durable trust persistence.
    pub fn new(persistence: Arc<dyn ProjectTrustPersistence>) -> Self {
        Self {
            persistence,
            byte_inspection: None,
        }
    }

    /// Attaches the stage-2 byte boundary so both stages share one authority.
    #[must_use]
    pub fn with_byte_inspection(mut self, port: Arc<dyn ProhibitedContentPort>) -> Self {
        self.byte_inspection = Some(port);
        self
    }

    fn load_record(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<ProjectTrustRecord, TrustAdmissionError> {
        self.persistence
            .load(project)
            .map_err(|_| TrustAdmissionError::AuthorityUnavailable)
    }

    /// Stage 1: pre-read admission over source metadata only.
    pub fn admit_source(
        &self,
        project: ProjectTrustProjectId,
        request: SourceAdmissionRequest<'_>,
    ) -> Result<SourceAdmission, TrustAdmissionError> {
        let record = self.load_record(project)?;
        if let Some(observed) = request.observed_token {
            // F1: foreign epochs are rejected before any revision logic, so
            // tokens from a deleted sidecar can never admit a recreated one.
            if observed.instance_epoch != record.instance_epoch {
                return Err(TrustAdmissionError::ForeignEpoch {
                    observed_epoch: observed.instance_epoch,
                    current_epoch: record.instance_epoch,
                });
            }
            if observed.revision != record.revision {
                return Err(TrustAdmissionError::StaleRevision {
                    observed: observed.revision,
                    current: record.revision,
                });
            }
        }
        if record.status == ProjectTrustStatus::Untrusted {
            return Err(TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::Untrusted,
            });
        }
        if request.channel.activation_gated() {
            return Err(TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::ChannelUnavailable,
            });
        }
        // Managed deny is never lifted by any permission mode (plan 18 §T1).
        if record.managed_deny_mask & request.channel.mask_bit() != 0 {
            return Err(TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::ManagedDeny,
            });
        }
        // F3: a file read names exactly one path; listing may name a root.
        if request.channel == SourceChannel::FilesRead && request.path.is_none() {
            return Err(TrustAdmissionError::MissingPath);
        }
        if let Some(path) = request.path {
            let components =
                normalize_source_path(path).map_err(|_| TrustAdmissionError::AmbiguousPath)?;
            if denied_by_frozen_set(&components) {
                return Err(TrustAdmissionError::DeniedByPolicy {
                    reason: SourceDenyReason::SensitivePath,
                });
            }
        }
        Ok(SourceAdmission {
            token: record.token(),
            policy_version: FROZEN_POLICY_VERSION,
        })
    }

    /// Stage 2: byte inspection on the canonical boundary, same authority.
    pub fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, TrustAdmissionError> {
        let port = self
            .byte_inspection
            .as_ref()
            .ok_or(TrustAdmissionError::AuthorityUnavailable)?;
        port.inspect(boundary, bytes).map_err(|error| match error {
            ContentGuardError::Unavailable => TrustAdmissionError::AuthorityUnavailable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_folding_covers_mixed_registry() {
        assert!(ascii_case_fold_bytes(b".ENV", b".env"));
        assert!(ascii_case_fold_bytes(b"ID_RSA", b"id_rsa"));
        assert!(!ascii_case_fold_bytes(b".envx", b".env"));
    }

    #[test]
    fn suffix_match_includes_exact_name_and_excludes_double_extension() {
        assert!(denied_by_frozen_set(&["host.key".to_string()]));
        assert!(denied_by_frozen_set(&[".key".to_string()]));
        assert!(denied_by_frozen_set(&[".KEY".to_string()]));
        assert!(!denied_by_frozen_set(&["notes.key.txt".to_string()]));
    }

    #[test]
    fn windows_drive_and_ads_forms_are_rejected() {
        assert_eq!(
            normalize_source_path("C:/x"),
            Err(PathRejection::ReservedCharacter)
        );
        assert_eq!(
            normalize_source_path("data/ads:stream"),
            Err(PathRejection::ReservedCharacter)
        );
    }
}

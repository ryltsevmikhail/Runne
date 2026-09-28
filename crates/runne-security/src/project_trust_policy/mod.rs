//! Single policy authority for T1 source admission (frozen inventory §F/S2).
//!
//! Stage 1 `admit_source` decides on metadata only, before any content is
//! read. Stage 2 byte inspection stays on the existing prohibited-content
//! boundary and is exposed through the same authority so callers observe one
//! authority and one epoch. Authority errors are fail-closed.

mod path;

pub use path::{
    FROZEN_DENY_COMPONENTS, FROZEN_DENY_PREFIXES, FROZEN_DENY_SUFFIXES, PathRejection,
    denied_by_frozen_set, normalize_source_path,
};

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::project_trust::{
    FROZEN_POLICY_VERSION, ProjectTrustControlLease, ProjectTrustEffectLease,
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus,
    SourceAdmission, SourceAdmissionRequest, SourceChannel, SourceDenyReason, TrustAdmissionError,
};
use std::sync::Arc;

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

    /// Whether the project carries an explicit trust record (T1 delivery
    /// governance applies only to governed projects).
    pub fn has_explicit_record(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<bool, TrustAdmissionError> {
        self.persistence
            .has_explicit_record(project)
            .map_err(|_| TrustAdmissionError::AuthorityUnavailable)
    }

    /// Acquires the runtime-owned user trust-control writer fence.
    pub fn acquire_control_lease(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<Box<dyn ProjectTrustControlLease>, TrustAdmissionError> {
        self.persistence
            .acquire_control_lease(project)
            .map_err(|_| TrustAdmissionError::AuthorityUnavailable)
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
        Self::admit_record(record, request)
    }

    /// Acquires the durable project-trust write fence and admits the current
    /// record with the ordinary source policy. The returned owned lease must
    /// be held only through the canonical effect-start commit, then dropped
    /// before any external I/O. Lock order is trust-sidecar lease followed by
    /// the short canonical effect-start transaction; no canonical transaction
    /// may be held while acquiring this lease.
    pub fn acquire_effect_lease(
        &self,
        project: ProjectTrustProjectId,
        request: SourceAdmissionRequest<'_>,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, TrustAdmissionError> {
        let lease = self
            .persistence
            .acquire_effect_lease(project)
            .map_err(|_| TrustAdmissionError::AuthorityUnavailable)?;
        let record = lease.record();
        if record.revision == 0 {
            return Err(TrustAdmissionError::DeniedByPolicy {
                reason: SourceDenyReason::Untrusted,
            });
        }
        Self::admit_record(record, request)?;
        Ok(lease)
    }

    fn admit_record(
        record: ProjectTrustRecord,
        request: SourceAdmissionRequest<'_>,
    ) -> Result<SourceAdmission, TrustAdmissionError> {
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
    fn frozen_version_pins_the_revision_two_deny_semantics() {
        // The revision bumped the frozen policy identity; consumers (pinned
        // claims, admissions) must observe the same generation.
        assert_eq!(FROZEN_POLICY_VERSION, 2);
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
        // Revision 2 keeps the rejection-not-repair discipline for the Win32
        // trailing-strip family (see path.rs tests for full coverage).
        assert_eq!(
            normalize_source_path("host.key."),
            Err(PathRejection::TrailingReservedSuffix)
        );
    }
}

#[cfg(test)]
mod effect_lease_tests;

use crate::updater_installed_metadata::{
    InstalledUpdateMetadataError, InstalledUpdateMetadataJournal,
};
use crate::updater_metadata::NativeEnrollmentArtifactPathsV1;
use crate::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleAdmission, UpdateInstallRecord,
    UpdateInstallState, UpdateTargetV2Binding, verify_update_v2,
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{UpdateCoordinator, UpdateCoordinatorError};

pub(super) fn ensure_staged_metadata(
    journal: &InstalledUpdateMetadataJournal,
    record: &UpdateInstallRecord,
) -> Result<(), InstalledUpdateMetadataError> {
    let Some((metadata, binding)) = journal.read()? else {
        return Err(InstalledUpdateMetadataError::Corrupt);
    };
    (record.metadata_sha256.as_deref() == Some(&binding)
        && metadata.targets.target.version == record.version
        && metadata.targets.target.artifact_sha256 == record.artifact_sha256)
        .then_some(())
        .ok_or(InstalledUpdateMetadataError::Corrupt)
}

impl UpdateCoordinator {
    /// Discards only an explicitly handled schema-v1 unbound updater transaction.
    pub fn discard_unbound_legacy_update(&self) -> Result<bool, UpdateCoordinatorError> {
        self.journal
            .discard_unbound_legacy()
            .map_err(UpdateCoordinatorError::Journal)
    }

    /// Re-verifies the committed installed release before admitting its tuple.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "fixed package-layout resolution is the remaining production integration step"
        )
    )]
    pub(crate) fn admit_installed_native_enrollment(
        &self,
        paths: &NativeEnrollmentArtifactPathsV1,
    ) -> Result<Option<NativeEnrollmentTupleAdmission>, UpdateCoordinatorError> {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        let artifacts = paths
            .measure()
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        self.admit_installed_native_enrollment_inner(now_unix_seconds, &artifacts)
    }

    #[cfg(test)]
    pub(crate) fn admit_installed_native_enrollment_at(
        &self,
        now_unix_seconds: u64,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Result<Option<NativeEnrollmentTupleAdmission>, UpdateCoordinatorError> {
        self.admit_installed_native_enrollment_inner(now_unix_seconds, artifacts)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "called only by the crate-private fixed-layout admission seam"
        )
    )]
    fn admit_installed_native_enrollment_inner(
        &self,
        now_unix_seconds: u64,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Result<Option<NativeEnrollmentTupleAdmission>, UpdateCoordinatorError> {
        let Some(record) = self.current()? else {
            return Ok(None);
        };
        if record.state != UpdateInstallState::Committed {
            return Ok(None);
        }
        let Some(trust_state) = self
            .trust_journal
            .read()
            .map_err(UpdateCoordinatorError::Trust)?
        else {
            return Ok(None);
        };
        if record.version != trust_state.installed_version {
            return Ok(None);
        }
        let Some((metadata, binding)) = self
            .installed_metadata
            .read()
            .map_err(UpdateCoordinatorError::InstalledMetadata)?
        else {
            return Ok(None);
        };
        if record.metadata_sha256.as_deref() != Some(&binding)
            || metadata.root.version < trust_state.root_version
            || metadata.snapshot.version < trust_state.snapshot_version
        {
            return Ok(None);
        }
        let binding = UpdateTargetV2Binding {
            product_id: &self.binding.product_id,
            platform: &self.binding.platform,
            arch: &self.binding.arch,
            min_os: &self.binding.min_os,
            profile_id: &self.binding.profile_id,
            bundle_sha256: &self.binding.bundle_sha256,
            runtime_version: &self.binding.runtime_version,
            runtime_digest: &self.binding.runtime_digest,
            channel: &self.binding.channel,
        };
        let verified = verify_update_v2(
            &metadata,
            &self.trust,
            &binding,
            now_unix_seconds,
            &trust_state.installed_version,
            &trust_state.rollback_floor,
        )
        .map_err(UpdateCoordinatorError::Verification)?;
        if verified.target().version != record.version
            || verified.target().artifact_sha256 != record.artifact_sha256
        {
            return Ok(None);
        }
        Ok(verified.admit_native_enrollment(artifacts))
    }
}

use crate::updater_installed_metadata::{
    InstalledUpdateMetadataError, InstalledUpdateMetadataJournal,
};
use crate::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleAdmission, UpdateInstallRecord,
    UpdateInstallState, UpdateTargetV2Binding, verify_update_v2,
};

use super::{UpdateCoordinator, UpdateCoordinatorError};

pub(super) fn ensure_staged_metadata(
    journal: &InstalledUpdateMetadataJournal,
    record: &UpdateInstallRecord,
) -> Result<(), InstalledUpdateMetadataError> {
    let Some(metadata) = journal.read()? else {
        return Err(InstalledUpdateMetadataError::Corrupt);
    };
    (metadata.targets.target.version == record.version
        && metadata.targets.target.artifact_sha256 == record.artifact_sha256)
        .then_some(())
        .ok_or(InstalledUpdateMetadataError::Corrupt)
}

impl UpdateCoordinator {
    /// Re-verifies the committed installed release before admitting its tuple.
    pub fn admit_installed_native_enrollment(
        &self,
        now_unix_seconds: u64,
        installed_version: &str,
        rollback_floor: &str,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Result<Option<NativeEnrollmentTupleAdmission>, UpdateCoordinatorError> {
        let Some(record) = self.current()? else {
            return Ok(None);
        };
        if record.state != UpdateInstallState::Committed || record.version != installed_version {
            return Ok(None);
        }
        let Some(trust_state) = self
            .trust_journal
            .read()
            .map_err(UpdateCoordinatorError::Trust)?
        else {
            return Ok(None);
        };
        if trust_state.installed_version != installed_version
            || trust_state.rollback_floor != rollback_floor
        {
            return Ok(None);
        }
        let Some(metadata) = self
            .installed_metadata
            .read()
            .map_err(UpdateCoordinatorError::InstalledMetadata)?
        else {
            return Ok(None);
        };
        if metadata.root.version < trust_state.root_version
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
            installed_version,
            rollback_floor,
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

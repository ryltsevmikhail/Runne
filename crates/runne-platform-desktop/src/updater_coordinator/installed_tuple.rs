use crate::updater_installed_metadata::{
    InstalledUpdateMetadataError, InstalledUpdateMetadataJournal,
};
use crate::{
    ConfirmedInstalledNativeEnrollment, MeasuredNativeEnrollmentArtifactsV1,
    NativeEnrollmentTupleAdmission, PreparedInstalledNativeEnrollment, UpdateInstallRecord,
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

    /// Re-verifies the committed installed release from the exact native package layout.
    #[cfg_attr(test, allow(dead_code))]
    pub fn prepare_installed_native_enrollment(
        &self,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        self.prepare_installed_native_enrollment_at(now_unix_seconds)
    }

    /// Revalidates a prompt-delayed native admission against current updater state.
    ///
    /// The original admission is consumed and only fresh retained evidence is returned.
    pub fn refresh_installed_native_enrollment(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        self.refresh_installed_native_enrollment_at_inner(prepared, now_unix_seconds)
    }

    /// Revalidates confirmed native evidence immediately before protected use.
    pub fn revalidate_confirmed_native_enrollment(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
    ) -> Result<bool, UpdateCoordinatorError> {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .as_secs();
        self.revalidate_confirmed_native_enrollment_at_inner(confirmed, now_unix_seconds)
    }

    fn prepare_installed_native_enrollment_at(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let Some(verified) = self.verified_installed_native_update(now_unix_seconds)? else {
            return Ok(None);
        };
        let paths = crate::updater_metadata::NativeEnrollmentArtifactPathsV1::resolve_installed()
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        let admission = paths
            .admit_verified(&verified)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        #[cfg(all(feature = "test-support", target_os = "macos"))]
        let admission = if runne_api::test_support::local_native_enrollment_enabled() {
            admission.and_then(|admission| admission.with_local_code_identities(&paths))
        } else {
            admission
        };
        Ok(admission.map(|admission| admission.retain_installed_paths(paths)))
    }

    fn refresh_installed_native_enrollment_at_inner(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
        now_unix_seconds: u64,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        let Some(fresh) = self.prepare_installed_native_enrollment_at(now_unix_seconds)? else {
            return Ok(None);
        };
        Ok(prepared.refresh_from(fresh))
    }

    fn revalidate_confirmed_native_enrollment_at_inner(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
        now_unix_seconds: u64,
    ) -> Result<bool, UpdateCoordinatorError> {
        let Some(verified) = self.verified_installed_native_update(now_unix_seconds)? else {
            return Ok(false);
        };
        let paths = crate::updater_metadata::NativeEnrollmentArtifactPathsV1::resolve_installed()
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?;
        Ok(paths
            .admit_verified(&verified)
            .map_err(|_| UpdateCoordinatorError::InvalidTransition)?
            .is_some_and(|admission| confirmed.matches_admission(&admission)))
    }

    #[cfg(test)]
    pub(crate) fn refresh_installed_native_enrollment_at(
        &self,
        prepared: PreparedInstalledNativeEnrollment,
        now_unix_seconds: u64,
    ) -> Result<Option<PreparedInstalledNativeEnrollment>, UpdateCoordinatorError> {
        self.refresh_installed_native_enrollment_at_inner(prepared, now_unix_seconds)
    }

    #[cfg(test)]
    pub(crate) fn test_only_revalidate_confirmed_native_enrollment_at(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
        now_unix_seconds: u64,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Result<bool, UpdateCoordinatorError> {
        self.test_support_revalidate_confirmed_at(confirmed, now_unix_seconds, artifacts)
    }

    #[cfg(any(
        test,
        all(feature = "test-support", target_os = "macos", target_arch = "aarch64")
    ))]
    pub(super) fn test_support_revalidate_confirmed_at(
        &self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
        now_unix_seconds: u64,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Result<bool, UpdateCoordinatorError> {
        Ok(self
            .verified_installed_native_update(now_unix_seconds)?
            .and_then(|verified| verified.admit_native_enrollment(artifacts))
            .is_some_and(|admission| confirmed.matches_admission(&admission)))
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
        Ok(self
            .verified_installed_native_update(now_unix_seconds)?
            .and_then(|verified| verified.admit_native_enrollment(artifacts)))
    }

    fn verified_installed_native_update(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Option<crate::VerifiedUpdateV2>, UpdateCoordinatorError> {
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
        Ok(Some(verified))
    }
}

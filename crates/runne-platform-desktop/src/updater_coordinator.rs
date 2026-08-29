//! Native updater orchestration around verified metadata and durable journals.

#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::updater_installed_metadata::{
    InstalledUpdateMetadataError, InstalledUpdateMetadataJournal,
};
use crate::{
    StagedUpdate, UpdateFeedClient, UpdateFeedError, UpdateInstallError, UpdateInstallPlan,
    UpdateInstallRecord, UpdateInstallState, UpdateJournal, UpdateJournalError,
    UpdateTargetV2Binding, UpdateTrustError, UpdateTrustJournal, UpdateTrustRootV2,
    VerifiedUpdateV2,
};

mod installed_tuple;

const MAX_BINDING_VALUE_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTargetBindingConfig {
    pub product_id: String,
    pub platform: String,
    pub arch: String,
    pub min_os: String,
    pub profile_id: String,
    pub bundle_sha256: String,
    pub runtime_version: String,
    pub runtime_digest: String,
    pub channel: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UpdateCoordinatorError {
    #[error("updater configuration is invalid")]
    InvalidConfiguration,
    #[error("updater feed operation failed")]
    Feed(#[source] UpdateFeedError),
    #[error("updater transaction operation failed")]
    Journal(#[source] UpdateJournalError),
    #[error("updater trust operation failed")]
    Trust(#[source] UpdateTrustError),
    #[error("installed update metadata operation failed")]
    InstalledMetadata(#[source] InstalledUpdateMetadataError),
    #[error("installed update metadata verification failed")]
    Verification(#[source] crate::UpdateV2VerificationError),
    #[error("active task runs require explicit update confirmation")]
    ActiveTaskRuns,
    #[error("updater transaction is already active")]
    TransactionActive,
    #[error("updater transaction transition is invalid")]
    InvalidTransition,
}

/// Native owner of feed verification, staging and restart transaction state.
pub struct UpdateCoordinator {
    feed: UpdateFeedClient,
    trust: UpdateTrustRootV2,
    binding: UpdateTargetBindingConfig,
    staging_directory: PathBuf,
    journal: UpdateJournal,
    trust_journal: UpdateTrustJournal,
    installed_metadata: InstalledUpdateMetadataJournal,
}

impl UpdateCoordinator {
    pub fn new(
        trust: UpdateTrustRootV2,
        binding: UpdateTargetBindingConfig,
        profile_directory: &Path,
    ) -> Result<Self, UpdateCoordinatorError> {
        validate_binding(&binding)?;
        let feed = UpdateFeedClient::new().map_err(UpdateCoordinatorError::Feed)?;
        let updates = profile_directory.join("updates");
        Ok(Self {
            feed,
            trust,
            binding,
            staging_directory: updates.join("staged"),
            journal: UpdateJournal::new(updates.join("install-state.json")),
            trust_journal: UpdateTrustJournal::new(updates.join("trust-state.json")),
            installed_metadata: InstalledUpdateMetadataJournal::new(
                updates.join("installed-metadata.json"),
            ),
        })
    }

    pub async fn check(
        &self,
        endpoint: &str,
        now_unix_seconds: u64,
        current_version: &str,
        rollback_floor: &str,
    ) -> Result<VerifiedUpdateV2, UpdateCoordinatorError> {
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
        self.feed
            .check_with_trust_journal(
                endpoint,
                &self.trust,
                &self.trust_journal,
                &binding,
                now_unix_seconds,
                current_version,
                rollback_floor,
            )
            .await
            .map_err(UpdateCoordinatorError::Feed)
    }

    pub async fn stage(
        &self,
        update: &VerifiedUpdateV2,
    ) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        if self
            .journal
            .read()
            .map_err(UpdateCoordinatorError::Journal)?
            .is_some()
        {
            return Err(UpdateCoordinatorError::TransactionActive);
        }
        let target = update.target();
        let path = self.staged_path(
            &target.version,
            &target.artifact_sha256,
            &target.artifact_url,
        )?;
        let staged = self
            .feed
            .download_and_stage(update, &path)
            .await
            .map_err(UpdateCoordinatorError::Feed)?;
        let metadata_sha256 = self
            .installed_metadata
            .persist(update)
            .map_err(UpdateCoordinatorError::InstalledMetadata)?;
        self.journal
            .record_staged_bound(&target.version, &staged, metadata_sha256)
            .map_err(UpdateCoordinatorError::Journal)?;
        self.journal
            .read()
            .map_err(UpdateCoordinatorError::Journal)?
            .ok_or(UpdateCoordinatorError::InvalidTransition)
    }

    pub fn prepare_restart(
        &self,
        active_task_runs: u64,
        confirm_active_task_runs: bool,
    ) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        let record = self.current_record()?;
        installed_tuple::ensure_staged_metadata(&self.installed_metadata, &record)
            .map_err(UpdateCoordinatorError::InstalledMetadata)?;
        if active_task_runs > 0 && !confirm_active_task_runs {
            return Err(UpdateCoordinatorError::ActiveTaskRuns);
        }
        let staged = StagedUpdate {
            path: record.staged_path.clone(),
            artifact_sha256: record.artifact_sha256,
        };
        UpdateInstallPlan::prepare(staged, active_task_runs, confirm_active_task_runs)
            .map_err(map_install_error)?
            .begin_restart()
            .map_err(map_install_error)?;
        self.journal
            .transition(UpdateInstallState::RestartRequired)
            .map_err(UpdateCoordinatorError::Journal)?;
        self.current_record()
    }

    /// Returns a prepared transaction to the staged state when installation
    /// could not be started by the native package backend.
    pub fn abort_restart(&self) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        self.require_state(UpdateInstallState::RestartRequired)?;
        self.journal
            .transition(UpdateInstallState::Staged)
            .map_err(UpdateCoordinatorError::Journal)?;
        self.current_record()
    }

    pub fn begin_health_check(&self) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        self.require_state(UpdateInstallState::RestartRequired)?;
        self.journal
            .transition(UpdateInstallState::HealthCheck)
            .map_err(UpdateCoordinatorError::Journal)?;
        self.current_record()
    }

    pub fn complete_health(
        &self,
        healthy: bool,
        installed_version: &str,
    ) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        let record = self.require_state(UpdateInstallState::HealthCheck)?;
        if healthy && record.version != installed_version {
            return Err(UpdateCoordinatorError::InvalidTransition);
        }
        if healthy {
            self.trust_journal
                .commit_install(installed_version)
                .map_err(UpdateCoordinatorError::Trust)?;
            self.journal
                .transition(UpdateInstallState::Committed)
                .map_err(UpdateCoordinatorError::Journal)?;
        } else {
            self.journal
                .transition(UpdateInstallState::RolledBack)
                .map_err(UpdateCoordinatorError::Journal)?;
        }
        self.current_record()
    }

    pub fn current(&self) -> Result<Option<UpdateInstallRecord>, UpdateCoordinatorError> {
        self.journal.read().map_err(UpdateCoordinatorError::Journal)
    }

    fn current_record(&self) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        self.current()?
            .ok_or(UpdateCoordinatorError::InvalidTransition)
    }

    fn require_state(
        &self,
        expected: UpdateInstallState,
    ) -> Result<UpdateInstallRecord, UpdateCoordinatorError> {
        let record = self.current_record()?;
        (record.state == expected)
            .then_some(record)
            .ok_or(UpdateCoordinatorError::InvalidTransition)
    }

    fn staged_path(
        &self,
        version: &str,
        digest: &str,
        artifact_url: &str,
    ) -> Result<PathBuf, UpdateCoordinatorError> {
        if crate::updater::parse_version(version).is_err()
            || !crate::updater::is_sha256(digest)
            || !self.staging_directory.is_absolute()
        {
            return Err(UpdateCoordinatorError::InvalidConfiguration);
        }
        let suffix = crate::UpdateArtifactKind::from_url(artifact_url)
            .map_err(|_| UpdateCoordinatorError::InvalidConfiguration)?
            .suffix();
        Ok(self
            .staging_directory
            .join(format!("runne-{version}-{digest}{suffix}")))
    }
}

fn validate_binding(binding: &UpdateTargetBindingConfig) -> Result<(), UpdateCoordinatorError> {
    let values = [
        &binding.product_id,
        &binding.platform,
        &binding.arch,
        &binding.min_os,
        &binding.profile_id,
        &binding.bundle_sha256,
        &binding.runtime_version,
        &binding.runtime_digest,
        &binding.channel,
    ];
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_BINDING_VALUE_BYTES)
    {
        return Err(UpdateCoordinatorError::InvalidConfiguration);
    }
    Ok(())
}

const fn map_install_error(error: UpdateInstallError) -> UpdateCoordinatorError {
    match error {
        UpdateInstallError::ActiveTaskRuns => UpdateCoordinatorError::ActiveTaskRuns,
        UpdateInstallError::InvalidTransition | UpdateInstallError::InvalidDigest => {
            UpdateCoordinatorError::InvalidTransition
        }
    }
}
#[cfg(test)]
mod tests {
    include!("updater_coordinator/tests.rs");
    include!("updater_coordinator/installed_tuple_tests.rs");
    include!("updater_coordinator/native_admission_tests.rs");
}

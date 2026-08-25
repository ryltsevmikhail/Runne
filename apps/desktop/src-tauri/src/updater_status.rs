use runne_platform_desktop::{
    UpdateInstallState, UpdateJournal, UpdateTrustJournal, VerifiedUpdateV2,
};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

use crate::updater_config::CompiledUpdater;

/// Renderer-safe updater state. Artifact paths, URLs and signatures stay native.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusSnapshot {
    pub state: &'static str,
    pub current_version: &'static str,
    pub available_version: Option<String>,
    pub artifact_sha256: Option<String>,
    pub reason: Option<&'static str>,
}

impl UpdateStatusSnapshot {
    /// Returns the explicit fail-closed state used until a trusted feed is available.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            state: "unavailable",
            current_version: env!("CARGO_PKG_VERSION"),
            available_version: None,
            artifact_sha256: None,
            reason: Some("metadata_source_unavailable"),
        }
    }

    #[must_use]
    const fn corrupt(reason: &'static str) -> Self {
        Self {
            state: "unavailable",
            current_version: env!("CARGO_PKG_VERSION"),
            available_version: None,
            artifact_sha256: None,
            reason: Some(reason),
        }
    }
}

/// Native owner of the persisted updater transaction state.
pub struct UpdateStatusStore {
    journal: UpdateJournal,
    trust_journal: UpdateTrustJournal,
    updater: Option<tokio::sync::Mutex<CompiledUpdater>>,
    candidate: Mutex<Option<VerifiedUpdateV2>>,
}

impl UpdateStatusStore {
    #[must_use]
    pub fn new(profile_directory: &Path) -> Self {
        Self {
            journal: UpdateJournal::new(profile_directory.join("updates/install-state.json")),
            trust_journal: UpdateTrustJournal::new(
                profile_directory.join("updates/trust-state.json"),
            ),
            updater: CompiledUpdater::load(profile_directory).map(tokio::sync::Mutex::new),
            candidate: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> UpdateStatusSnapshot {
        if self.trust_journal.read().is_err() {
            return UpdateStatusSnapshot::corrupt("trust_state_corrupt");
        }
        match self.journal.read() {
            Ok(Some(record)) => UpdateStatusSnapshot {
                state: state_name(record.state),
                current_version: env!("CARGO_PKG_VERSION"),
                available_version: Some(record.version),
                artifact_sha256: Some(record.artifact_sha256),
                reason: None,
            },
            Ok(None) => self.candidate_snapshot(),
            Err(_) => UpdateStatusSnapshot::corrupt("transaction_state_corrupt"),
        }
    }

    pub(crate) async fn check_update(&self) -> Result<(), ()> {
        let updater = self.updater.as_ref().ok_or(())?;
        let updater = updater.lock().await;
        let candidate = updater
            .coordinator
            .check(
                updater.endpoint,
                unix_now(),
                env!("CARGO_PKG_VERSION"),
                updater.rollback_floor,
            )
            .await
            .map_err(|_| ())?;
        drop(updater);
        *self.candidate.lock().map_err(|_| ())? = Some(candidate);
        Ok(())
    }

    pub(crate) async fn download_update(&self) -> Result<(), ()> {
        let candidate = self.candidate.lock().map_err(|_| ())?.clone().ok_or(())?;
        let updater = self.updater.as_ref().ok_or(())?;
        let updater = updater.lock().await;
        updater
            .coordinator
            .stage(&candidate)
            .await
            .map_err(|_| ())?;
        drop(updater);
        *self.candidate.lock().map_err(|_| ())? = None;
        Ok(())
    }

    pub(crate) fn prepare_update_install(
        &self,
        active_task_runs: u64,
        confirm_active_task_runs: bool,
    ) -> Result<(), ()> {
        let updater = self.updater.as_ref().ok_or(())?;
        let updater = updater.try_lock().map_err(|_| ())?;
        updater
            .coordinator
            .prepare_restart(active_task_runs, confirm_active_task_runs)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn candidate_snapshot(&self) -> UpdateStatusSnapshot {
        let Ok(candidate) = self.candidate.lock() else {
            return UpdateStatusSnapshot::corrupt("candidate_state_unavailable");
        };
        candidate
            .as_ref()
            .map_or_else(UpdateStatusSnapshot::unavailable, |value| {
                UpdateStatusSnapshot {
                    state: "available",
                    current_version: env!("CARGO_PKG_VERSION"),
                    available_version: Some(value.target().version.clone()),
                    artifact_sha256: Some(value.target().artifact_sha256.clone()),
                    reason: None,
                }
            })
    }

    #[cfg(test)]
    const fn journal(&self) -> &UpdateJournal {
        &self.journal
    }

    #[cfg(test)]
    const fn trust_journal(&self) -> &UpdateTrustJournal {
        &self.trust_journal
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

const fn state_name(state: UpdateInstallState) -> &'static str {
    match state {
        UpdateInstallState::Staged => "staged",
        UpdateInstallState::RestartRequired => "restart_required",
        UpdateInstallState::HealthCheck => "health_check",
        UpdateInstallState::Committed => "committed",
        UpdateInstallState::RolledBack => "rolled_back",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn status_store_restores_native_transaction_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = UpdateStatusStore::new(directory.path());
        assert_eq!(store.snapshot(), UpdateStatusSnapshot::unavailable());
        let digest = "a".repeat(64);
        store
            .journal()
            .record_staged(
                "1.2.3",
                &runne_platform_desktop::StagedUpdate {
                    path: PathBuf::from("/tmp/runne-update.bin"),
                    artifact_sha256: digest.clone(),
                },
            )
            .unwrap();
        let snapshot = store.snapshot();
        assert_eq!(snapshot.state, "staged");
        assert_eq!(snapshot.available_version.as_deref(), Some("1.2.3"));
        assert_eq!(snapshot.artifact_sha256.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn status_store_fails_closed_when_trust_state_is_corrupt() {
        let directory = tempfile::tempdir().unwrap();
        let store = UpdateStatusStore::new(directory.path());
        store.trust_journal().initialize("1.0.0", "1.0.0").unwrap();
        std::fs::write(
            directory.path().join("updates/trust-state.json.1.json"),
            b"not-json",
        )
        .unwrap();
        assert_eq!(store.snapshot().reason, Some("trust_state_corrupt"));
    }
}

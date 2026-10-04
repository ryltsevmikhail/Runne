use super::saved_remote_recovery::SavedRemoteRecoveryCandidate;
use super::*;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_provider::ProviderResponseIdentityCommitter;
use runne_provider::{ProviderRecoveryRequest, ProviderRemoteResponseStatus};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use std::sync::Arc;

/// Factual result of one bounded remote status operation; contains no remote ID or output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedRemoteObservationOutcome {
    #[cfg(test)]
    NoCandidate,
    Unsupported,
    Pending,
    Unknown,
    TerminalArtifactPendingLocalRecovery,
    TerminalArtifactApplied,
}

impl DaemonCanonicalProviderService {
    /// Checks exactly one saved response and persists the observation before returning.
    #[cfg(test)]
    pub(crate) async fn observe_saved_remote_attempt(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<SavedRemoteObservationOutcome, DaemonError> {
        let Some(candidate) = self
            .classify_saved_remote_attempt_bounded(taskrun, task_attempt)
            .await?
        else {
            return Ok(SavedRemoteObservationOutcome::NoCandidate);
        };
        self.observe_saved_remote_candidate(candidate).await
    }

    /// Observes one previously classified candidate without repeating its
    /// synchronous identity/authentication work on the async worker thread.
    pub(crate) async fn observe_saved_remote_candidate(
        &self,
        candidate: SavedRemoteRecoveryCandidate,
    ) -> Result<SavedRemoteObservationOutcome, DaemonError> {
        let Some(route) = self.secondary_profile.as_ref() else {
            return Ok(SavedRemoteObservationOutcome::Unsupported);
        };
        let id = candidate.dispatch_attempt_id;
        let Some(attempt_guard) = self.saved_remote_gate.reserve_attempt(id) else {
            return Ok(SavedRemoteObservationOutcome::Unknown);
        };
        let profile = Arc::clone(&route.profile);
        let profile_for_preparation = Arc::clone(&profile);
        let execution_store = Arc::clone(&self.execution_store);
        let keyring = Arc::clone(&self.keyring);
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Ok(SavedRemoteObservationOutcome::Unknown);
        };
        let preparation_guard = Arc::clone(&attempt_guard);
        let prepared = tokio::task::spawn_blocking(
            move || -> Result<PreparedRemoteObservation, &'static str> {
                let _permit = permit;
                let _attempt_guard = preparation_guard;
                let snapshot = execution_store
                    .load_remote_attempt(id)
                    .map_err(|_| "provider recovery snapshot unavailable")?
                    .ok_or("provider recovery snapshot missing")?;
                let binding = runne_provider::ProviderRecoveryBinding::new(
                    candidate.taskrun_id,
                    candidate.task_attempt_id,
                    id,
                    snapshot.request.binding.profile_digest,
                )
                .map_err(|_| "provider recovery binding invalid")?;
                let committer = RuntimeProviderRemoteIdentityCommitter::new(
                    Arc::clone(&keyring),
                    Arc::clone(&execution_store),
                );
                if snapshot.terminal.is_some() {
                    committer
                        .commit_authenticated_remote_terminal_source(
                            binding,
                            profile_for_preparation.as_ref(),
                        )
                        .map_err(|_| "provider terminal source unavailable")?;
                    Ok(PreparedRemoteObservation::TerminalSourceCommitted)
                } else {
                    let saved = committer
                        .load_persisted_attempt(binding)
                        .map_err(|_| "provider recovery identity unavailable")?
                        .ok_or("provider recovery identity missing")?;
                    Ok(PreparedRemoteObservation::NeedsStatusCheck {
                        binding,
                        saved: Box::new(saved),
                    })
                }
            },
        )
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery preparation unavailable".into()))?
        .map_err(|message| DaemonError::Bootstrap(message.into()))?;
        let (binding, saved) = match prepared {
            PreparedRemoteObservation::TerminalSourceCommitted => {
                return self
                    .finish_terminal_observation(
                        id,
                        profile,
                        candidate.accepted_cancel_requested,
                        Arc::clone(&attempt_guard),
                    )
                    .await;
            }
            PreparedRemoteObservation::NeedsStatusCheck { binding, saved } => (binding, *saved),
        };
        if !candidate.status_check_supported && !candidate.remote_cancel_requested {
            return Ok(SavedRemoteObservationOutcome::Unsupported);
        }
        let response_id = saved
            .response_id()
            .cloned()
            .ok_or_else(|| DaemonError::Bootstrap("provider response identity missing".into()))?;
        let request =
            ProviderRecoveryRequest::new_exact(binding, response_id, saved.identity().clone())
                .map_err(|_| DaemonError::Bootstrap("provider recovery request invalid".into()))?;
        let check = match check_saved_response(route.adapter.as_ref(), &candidate, request).await {
            Ok(check) => check,
            Err(SavedRemoteObservationOutcome::Unknown) => {
                return Ok(SavedRemoteObservationOutcome::Unknown);
            }
            Err(outcome) => return Ok(outcome),
        };
        let prohibited = Arc::clone(&self.prohibited_content);
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Ok(SavedRemoteObservationOutcome::Unknown);
        };
        let scan_guard = Arc::clone(&attempt_guard);
        let Some(check) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _attempt_guard = scan_guard;
            sanitize_remote_terminal(prohibited.as_ref(), &saved, check)
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider terminal scan unavailable".into()))?
        else {
            return Ok(SavedRemoteObservationOutcome::Unknown);
        };
        let terminal = check.terminal().is_some();
        let status = check.status().clone();
        let execution_store = Arc::clone(&self.execution_store);
        let keyring = Arc::clone(&self.keyring);
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Ok(SavedRemoteObservationOutcome::Unknown);
        };
        let persistence_guard = Arc::clone(&attempt_guard);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _attempt_guard = persistence_guard;
            let committer = RuntimeProviderRemoteIdentityCommitter::new(keyring, execution_store);
            tokio::runtime::Handle::current().block_on(committer.persist_remote_check(&check))
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery persistence unavailable".into()))?
        .map_err(|_| DaemonError::Bootstrap("provider recovery persistence unavailable".into()))?;
        if terminal {
            let profile = Arc::clone(&route.profile);
            let keyring = Arc::clone(&self.keyring);
            let execution_store = Arc::clone(&self.execution_store);
            let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
                return Ok(SavedRemoteObservationOutcome::Unknown);
            };
            let source_guard = Arc::clone(&attempt_guard);
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let _attempt_guard = source_guard;
                let committer =
                    RuntimeProviderRemoteIdentityCommitter::new(keyring, execution_store);
                committer.commit_authenticated_remote_terminal_source(binding, profile.as_ref())
            })
            .await
            .map_err(|_| DaemonError::Bootstrap("provider terminal source unavailable".into()))?
            .map_err(|_| DaemonError::Bootstrap("provider terminal source unavailable".into()))?;
            self.finish_terminal_observation(
                id,
                Arc::clone(&route.profile),
                candidate.accepted_cancel_requested,
                Arc::clone(&attempt_guard),
            )
            .await
        } else if matches!(status, ProviderRemoteResponseStatus::Pending) {
            Ok(SavedRemoteObservationOutcome::Pending)
        } else {
            Ok(SavedRemoteObservationOutcome::Unknown)
        }
    }

    async fn finish_terminal_observation(
        &self,
        id: runne_provider::DispatchAttemptId,
        profile: Arc<SharedTextProviderProfile>,
        cancellation_owner: bool,
        attempt_guard: Arc<super::saved_remote_gate::SavedRemoteAttemptGuard>,
    ) -> Result<SavedRemoteObservationOutcome, DaemonError> {
        if self
            .apply_saved_remote_terminal(id, profile, cancellation_owner, attempt_guard)
            .await?
        {
            Ok(SavedRemoteObservationOutcome::TerminalArtifactApplied)
        } else {
            Ok(SavedRemoteObservationOutcome::TerminalArtifactPendingLocalRecovery)
        }
    }
}

enum PreparedRemoteObservation {
    TerminalSourceCommitted,
    NeedsStatusCheck {
        binding: runne_provider::ProviderRecoveryBinding,
        saved: Box<runne_runtime::provider_execution::RecoveredProviderRemoteAttempt>,
    },
}

#[path = "saved_remote_observe/remote_check.rs"]
mod remote_check;
#[cfg(test)]
use remote_check::SavedRemoteRecoveryAdapter;
use remote_check::{check_saved_response, sanitize_remote_terminal};

#[cfg(test)]
#[path = "saved_remote_observe_tests.rs"]
mod tests;

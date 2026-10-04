use super::*;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_provider::DispatchAttemptId;
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;

#[cfg(test)]
#[path = "saved_remote_recovery/legacy_page.rs"]
mod legacy_page;

/// Safe metadata for one authenticated saved-response attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SavedRemoteRecoveryCandidate {
    pub(crate) dispatch_attempt_id: DispatchAttemptId,
    pub(crate) taskrun_id: runne_domain::id::TaskRunId,
    pub(crate) task_attempt_id: runne_domain::id::AttemptId,
    pub(crate) status_check_supported: bool,
    pub(crate) accepted_cancel_requested: bool,
    pub(crate) remote_cancel_requested: bool,
}

/// Fair keyset page; it contains no request, output, credential or remote ID.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SavedRemoteRecoveryPage {
    pub(crate) candidates: Vec<SavedRemoteRecoveryCandidate>,
    pub(crate) next_after: Option<DispatchAttemptId>,
    pub(crate) reached_end: bool,
    pub(crate) unavailable_count: u64,
}

impl DaemonCanonicalProviderService {
    /// Scans the raw keyset page off-thread without queueing unbounded work.
    pub(crate) async fn scan_saved_remote_candidate_ids_bounded(
        &self,
        after: Option<DispatchAttemptId>,
        limit: usize,
    ) -> Result<runne_application::provider::ProviderRemoteAttemptPage, DaemonError> {
        if !(1..=4).contains(&limit) {
            return Err(DaemonError::Bootstrap(
                "provider recovery page invalid".into(),
            ));
        }
        let Some(permit) = self.saved_remote_gate.reserve_scan() else {
            return Err(DaemonError::Bootstrap(
                "provider recovery worker busy".into(),
            ));
        };
        let store = Arc::clone(&self.execution_store);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.scan_remote_attempts(after, limit)
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery scan unavailable".into()))?
        .map_err(|_| DaemonError::Bootstrap("provider recovery scan unavailable".into()))
    }

    /// Classifies one raw ID off-thread under the same bounded worker gate.
    pub(crate) async fn classify_saved_remote_candidate_by_id_bounded(
        &self,
        id: DispatchAttemptId,
    ) -> Result<Option<SavedRemoteRecoveryCandidate>, DaemonError> {
        let Some(route) = self.secondary_profile.as_ref() else {
            return Ok(None);
        };
        let caps = route.adapter.recovery_capabilities();
        let route = SavedRemoteRecoveryRoute::from(route);
        let store = Arc::clone(&self.execution_store);
        let keyring = Arc::clone(&self.keyring);
        let Some(attempt_guard) = self.saved_remote_gate.reserve_attempt(id) else {
            return Err(DaemonError::Bootstrap(
                "provider recovery candidate already active".into(),
            ));
        };
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Err(DaemonError::Bootstrap(
                "provider recovery worker busy".into(),
            ));
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _attempt_guard = attempt_guard;
            Self::classify_saved_remote_attempt_by_id(
                &store,
                &keyring,
                id,
                route,
                caps.status_check,
                caps.remote_cancel,
            )
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery identity unavailable".into()))?
    }

    /// Finds and classifies one assignment off-thread under one bounded permit.
    #[cfg(test)]
    pub(crate) async fn classify_saved_remote_attempt_bounded(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<SavedRemoteRecoveryCandidate>, DaemonError> {
        let Some(route) = self.secondary_profile.as_ref() else {
            return Ok(None);
        };
        let caps = route.adapter.recovery_capabilities();
        let route = SavedRemoteRecoveryRoute::from(route);
        let store = Arc::clone(&self.execution_store);
        let keyring = Arc::clone(&self.keyring);
        let gate = Arc::clone(&self.saved_remote_gate);
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Err(DaemonError::Bootstrap(
                "provider recovery worker busy".into(),
            ));
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let id = store
                .find_remote_attempt(taskrun, task_attempt)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider recovery lookup unavailable".into())
                })?;
            let Some(id) = id else { return Ok(None) };
            let Some(_attempt_guard) = gate.reserve_attempt(id) else {
                return Err(DaemonError::Bootstrap(
                    "provider recovery candidate already active".into(),
                ));
            };
            Self::classify_saved_remote_attempt_by_id(
                &store,
                &keyring,
                id,
                route,
                caps.status_check,
                caps.remote_cancel,
            )
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery identity unavailable".into()))?
    }

    fn classify_saved_remote_attempt_by_id(
        execution_store: &Arc<SqliteProviderExecutionStore>,
        keyring: &Arc<dyn ProviderJournalKeyring>,
        id: DispatchAttemptId,
        route: SavedRemoteRecoveryRoute,
        status_check_supported: bool,
        remote_cancel_supported: bool,
    ) -> Result<Option<SavedRemoteRecoveryCandidate>, DaemonError> {
        let Some((request, response)) = execution_store
            .load_remote_identity(id)
            .map_err(|_| DaemonError::Bootstrap("provider recovery identity unavailable".into()))?
        else {
            return Err(DaemonError::Bootstrap(
                "provider recovery identity missing".into(),
            ));
        };
        if request.binding.dispatch_attempt_id != id
            || response
                .as_ref()
                .is_none_or(|value| value.binding != request.binding || value.key != request.key)
        {
            return Err(DaemonError::Bootstrap(
                "provider recovery identity invalid".into(),
            ));
        }
        let binding = &request.binding;
        if binding.provider_id != route.provider_id
            || binding.credential_realm != route.provider_id
            || binding.profile_id != route.profile.profile_id()
            || binding.profile_digest != route.profile.profile_digest()
            || binding.pricing_digest != route.profile.pricing_revision_digest()
        {
            return Ok(None);
        }
        let recovery_binding = runne_provider::ProviderRecoveryBinding::new(
            binding.taskrun_id,
            binding.taskrun_attempt_id,
            id,
            binding.profile_digest,
        )
        .map_err(|_| DaemonError::Bootstrap("provider recovery binding invalid".into()))?;
        let committer = RuntimeProviderRemoteIdentityCommitter::new(
            Arc::clone(keyring),
            Arc::clone(execution_store),
        );
        let saved = committer
            .load_persisted_attempt(recovery_binding)
            .map_err(|_| DaemonError::Bootstrap("provider recovery identity unavailable".into()))?
            .ok_or_else(|| DaemonError::Bootstrap("provider recovery identity missing".into()))?;
        if saved.response_id().is_none()
            || saved.identity().provider_id().as_str() != route.provider_id
            || saved.identity().credential_realm().as_str() != route.provider_id
            || saved.identity().profile_id() != route.profile.profile_id()
        {
            return Ok(None);
        }
        let accepted_cancel_requested = execution_store
            .remote_cancel_requested(binding)
            .map_err(|_| DaemonError::Bootstrap("provider cancel proof unavailable".into()))?;
        Ok(Some(SavedRemoteRecoveryCandidate {
            dispatch_attempt_id: id,
            taskrun_id: binding.taskrun_id,
            task_attempt_id: binding.taskrun_attempt_id,
            status_check_supported,
            accepted_cancel_requested,
            remote_cancel_requested: remote_cancel_supported && accepted_cancel_requested,
        }))
    }
}

struct SavedRemoteRecoveryRoute {
    profile: Arc<SharedTextProviderProfile>,
    provider_id: String,
}

impl From<&super::execution::SecondaryProfileRoute> for SavedRemoteRecoveryRoute {
    fn from(route: &super::execution::SecondaryProfileRoute) -> Self {
        Self {
            profile: Arc::clone(&route.profile),
            provider_id: route.provider_id.to_string(),
        }
    }
}

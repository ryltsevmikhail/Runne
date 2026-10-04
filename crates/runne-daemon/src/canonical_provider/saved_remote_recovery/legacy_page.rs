use super::super::*;
use super::{SavedRemoteRecoveryPage, SavedRemoteRecoveryRoute};
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_provider::DispatchAttemptId;

impl DaemonCanonicalProviderService {
    /// Returns one bounded page of exact supported saved-ID attempts.
    pub(crate) fn scan_saved_remote_candidates(
        &self,
        after: Option<DispatchAttemptId>,
        limit: usize,
    ) -> Result<SavedRemoteRecoveryPage, DaemonError> {
        let Some(route) = self.secondary_profile.as_ref() else {
            return Ok(SavedRemoteRecoveryPage {
                candidates: Vec::new(),
                next_after: None,
                reached_end: true,
                unavailable_count: 0,
            });
        };
        if !(1..=16).contains(&limit) {
            return Err(DaemonError::Bootstrap(
                "provider recovery page invalid".into(),
            ));
        }
        let caps = route.adapter.recovery_capabilities();
        let page = self
            .execution_store
            .scan_remote_attempts(after, limit)
            .map_err(|_| DaemonError::Bootstrap("provider recovery scan unavailable".into()))?;
        let mut candidates = Vec::new();
        let mut unavailable_count = 0_u64;
        for id in page.attempts.iter().copied() {
            match Self::classify_saved_remote_attempt_by_id(
                &self.execution_store,
                &self.keyring,
                id,
                SavedRemoteRecoveryRoute::from(route),
                caps.status_check,
                caps.remote_cancel,
            ) {
                Ok(Some(candidate)) => candidates.push(candidate),
                Ok(None) => {}
                Err(_) => unavailable_count = unavailable_count.saturating_add(1),
            }
        }
        Ok(SavedRemoteRecoveryPage {
            candidates,
            next_after: page.next_after,
            reached_end: page.reached_end,
            unavailable_count,
        })
    }
}

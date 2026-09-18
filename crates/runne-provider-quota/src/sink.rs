use crate::{
    QuotaDecision, QuotaIdentity, QuotaModelError, QuotaRefreshStatus, QuotaSnapshot, QuotaState,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const DEFAULT_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_VERSIONS_PER_PROVIDER: usize = 8;

/// Provider-neutral sink for non-secret quota evidence.
pub trait QuotaEvidenceSink: Send + Sync {
    /// Returns the current fail-closed admission decision for a credential.
    fn admission(&self, identity: &QuotaIdentity, now_unix_seconds: u64) -> QuotaDecision {
        let _ = (identity, now_unix_seconds);
        QuotaDecision::AllowUnknown
    }

    /// Records token usage observed after a completed provider call.
    fn record_usage(
        &self,
        identity: &QuotaIdentity,
        input_tokens: u64,
        output_tokens: u64,
        observed_at_unix_seconds: u64,
    ) -> Result<(), QuotaSinkError>;
    /// Records a provider-attested snapshot from an authorized operation.
    fn record_snapshot(&self, snapshot: QuotaSnapshot) -> Result<(), QuotaSinkError>;
    /// Records a sanitized failure without changing a prior trusted snapshot.
    fn record_refresh_failure(
        &self,
        identity: &QuotaIdentity,
        status: QuotaRefreshStatus,
    ) -> Result<(), QuotaSinkError>;
}

/// Errors returned when quota evidence cannot be retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QuotaSinkError {
    /// The process-local state lock was poisoned.
    #[error("quota state lock poisoned")]
    LockPoisoned,
    /// Evidence failed model validation.
    #[error("quota evidence rejected: {0}")]
    Model(#[from] QuotaModelError),
}

/// Process-local quota state shared by provider effects and runtime status.
#[derive(Clone, Default)]
pub struct QuotaStateStore {
    states: Arc<Mutex<BTreeMap<(String, u64), QuotaState>>>,
}

impl QuotaStateStore {
    /// Creates an empty state store. No credentials or provider responses are retained.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a cloned state for a provider/version identity.
    pub fn state(&self, identity: &QuotaIdentity) -> Result<Option<QuotaState>, QuotaSinkError> {
        self.states
            .lock()
            .map(|states| {
                states
                    .get(&(
                        identity.provider_id().to_owned(),
                        identity.credential_version(),
                    ))
                    .cloned()
            })
            .map_err(|_| QuotaSinkError::LockPoisoned)
    }

    /// Returns bounded, non-secret states for one provider ordered by version.
    pub fn states_for_provider(
        &self,
        provider_id: &str,
    ) -> Result<Vec<QuotaState>, QuotaSinkError> {
        self.states
            .lock()
            .map(|states| {
                states
                    .iter()
                    .filter(|((provider, _), _)| provider == provider_id)
                    .map(|(_, state)| state.clone())
                    .collect()
            })
            .map_err(|_| QuotaSinkError::LockPoisoned)
    }

    /// Removes old credential-version state while retaining the active version.
    pub fn prune_provider_versions(
        &self,
        provider_id: &str,
        active_version: u64,
    ) -> Result<usize, QuotaSinkError> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| QuotaSinkError::LockPoisoned)?;
        Ok(prune_locked(&mut states, provider_id, active_version))
    }

    /// Returns the fail-closed decision for an existing state.
    pub fn admission(
        &self,
        identity: &QuotaIdentity,
        now_unix_seconds: u64,
    ) -> Result<QuotaDecision, QuotaSinkError> {
        Ok(self
            .state(identity)?
            .map_or(QuotaDecision::AllowUnknown, |state| {
                state.decision(now_unix_seconds)
            }))
    }

    fn with_state<T>(
        &self,
        identity: &QuotaIdentity,
        operation: impl FnOnce(&mut QuotaState) -> Result<T, QuotaModelError>,
    ) -> Result<T, QuotaSinkError> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| QuotaSinkError::LockPoisoned)?;
        prune_locked(
            &mut states,
            identity.provider_id(),
            identity.credential_version(),
        );
        let key = (
            identity.provider_id().to_owned(),
            identity.credential_version(),
        );
        let state = states
            .entry(key)
            .or_insert_with(|| QuotaState::new(identity.clone(), DEFAULT_MAX_AGE_SECONDS));
        operation(state).map_err(QuotaSinkError::Model)
    }
}

fn prune_locked(
    states: &mut BTreeMap<(String, u64), QuotaState>,
    provider_id: &str,
    active_version: u64,
) -> usize {
    let versions: Vec<u64> = states
        .keys()
        .filter_map(|(provider, version)| (provider == provider_id).then_some(*version))
        .collect();
    if versions.len() <= MAX_VERSIONS_PER_PROVIDER {
        return 0;
    }
    let mut keep = versions
        .iter()
        .copied()
        .filter(|version| *version == active_version)
        .take(1)
        .collect::<Vec<_>>();
    keep.extend(
        versions
            .iter()
            .copied()
            .filter(|version| *version != active_version),
    );
    let active_present = keep.contains(&active_version);
    keep.sort_unstable_by(|left, right| right.cmp(left));
    keep.truncate(if active_present {
        MAX_VERSIONS_PER_PROVIDER
    } else {
        MAX_VERSIONS_PER_PROVIDER - 1
    });
    keep.sort_unstable();
    let before = versions_len(states, provider_id);
    states.retain(|(provider, version), _| {
        provider != provider_id || keep.binary_search(version).is_ok()
    });
    before - versions_len(states, provider_id)
}

fn versions_len(states: &BTreeMap<(String, u64), QuotaState>, provider_id: &str) -> usize {
    states
        .keys()
        .filter(|(provider, _)| provider == provider_id)
        .count()
}

impl QuotaEvidenceSink for QuotaStateStore {
    fn admission(&self, identity: &QuotaIdentity, now_unix_seconds: u64) -> QuotaDecision {
        self.admission(identity, now_unix_seconds)
            .unwrap_or(QuotaDecision::Unavailable)
    }

    fn record_usage(
        &self,
        identity: &QuotaIdentity,
        input_tokens: u64,
        output_tokens: u64,
        observed_at_unix_seconds: u64,
    ) -> Result<(), QuotaSinkError> {
        self.with_state(identity, |state| {
            state.record_usage(
                identity,
                input_tokens,
                output_tokens,
                observed_at_unix_seconds,
            )
        })
    }

    fn record_snapshot(&self, snapshot: QuotaSnapshot) -> Result<(), QuotaSinkError> {
        let identity = snapshot.identity().clone();
        self.with_state(&identity, |state| state.apply_snapshot(snapshot))
    }

    fn record_refresh_failure(
        &self,
        identity: &QuotaIdentity,
        status: QuotaRefreshStatus,
    ) -> Result<(), QuotaSinkError> {
        self.with_state(identity, |state| {
            state.record_refresh_failure(status);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_prunes_old_versions_but_keeps_active() {
        let store = QuotaStateStore::new();
        for version in 1..=10 {
            let identity = QuotaIdentity::new("rotation", version).unwrap();
            store.record_usage(&identity, 1, 1, version).unwrap();
        }
        let states = store.states_for_provider("rotation").unwrap();
        assert_eq!(states.len(), MAX_VERSIONS_PER_PROVIDER);
        assert!(
            states
                .iter()
                .any(|state| state.identity().credential_version() == 10)
        );
        assert_eq!(store.prune_provider_versions("rotation", 10).unwrap(), 0);
    }
}

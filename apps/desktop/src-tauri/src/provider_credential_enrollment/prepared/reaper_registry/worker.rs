use std::sync::Arc;

#[cfg(test)]
use super::ReaperOperationId;
use super::{
    CredentialWriterReaperLastError, CredentialWriterReaperState, ExactWriterCleanup, ReaperEntry,
    RegistryCore, recover_lock,
};

#[derive(Clone, Copy)]
pub(super) enum AttemptKind {
    OuterRetry,
    Maintenance,
    Shutdown,
}

pub(super) fn maintenance_loop<C: ExactWriterCleanup + Send + 'static>(core: &RegistryCore<C>) {
    loop {
        let (state, _) = core
            .wake
            .wait_timeout_while(recover_lock(&core.state), core.cadence, |state| {
                !state.stopping
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stopping = state.stopping;
        drop(state);
        let entries = eligible_entries(core, stopping);
        for entry in entries {
            attempt_entry(
                &entry,
                if stopping {
                    AttemptKind::Shutdown
                } else {
                    AttemptKind::Maintenance
                },
            );
        }
        if stopping {
            return;
        }
    }
}

pub(super) fn eligible_entries<C>(
    core: &RegistryCore<C>,
    final_attempt: bool,
) -> Vec<Arc<ReaperEntry<C>>> {
    recover_lock(&core.state)
        .entries
        .iter()
        .filter(|entry| {
            let status = recover_lock(&entry.status);
            status.owner_retained && (final_attempt || status.eligible)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
pub(super) fn matching_entries<C>(
    core: &RegistryCore<C>,
    operation: &ReaperOperationId,
    eligible_only: bool,
) -> Vec<Arc<ReaperEntry<C>>> {
    recover_lock(&core.state)
        .entries
        .iter()
        .filter(|entry| {
            let status = recover_lock(&entry.status);
            entry.operation == *operation
                && status.owner_retained
                && (!eligible_only || status.eligible)
        })
        .cloned()
        .collect()
}

pub(super) fn attempt_entry<C: ExactWriterCleanup>(entry: &ReaperEntry<C>, kind: AttemptKind) {
    let mut slot = recover_lock(&entry.owner);
    let Some(mut owner) = slot.take() else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match kind {
        AttemptKind::OuterRetry => owner.retry_exact(),
        AttemptKind::Maintenance | AttemptKind::Shutdown => owner.maintain_exact(),
    }));
    match result {
        Ok(Ok(())) => {
            drop(owner);
            drop(slot);
            let mut status = recover_lock(&entry.status);
            status.attempts = status.attempts.saturating_add(1);
            status.state = CredentialWriterReaperState::Reaped;
            status.owner_retained = false;
            status.eligible = false;
        }
        Ok(Err(_)) => {
            *slot = Some(owner);
            drop(slot);
            let mut status = recover_lock(&entry.status);
            status.attempts = status.attempts.saturating_add(1);
            status.state = CredentialWriterReaperState::Failed;
            status.owner_retained = true;
            status.last_error = Some(match kind {
                AttemptKind::OuterRetry => CredentialWriterReaperLastError::OuterRetry,
                AttemptKind::Maintenance => CredentialWriterReaperLastError::Maintenance,
                AttemptKind::Shutdown => CredentialWriterReaperLastError::Shutdown,
            });
        }
        Err(_) => {
            *slot = Some(owner);
            drop(slot);
            let mut status = recover_lock(&entry.status);
            status.attempts = status.attempts.saturating_add(1);
            status.state = CredentialWriterReaperState::Failed;
            status.owner_retained = true;
            status.last_error = Some(CredentialWriterReaperLastError::Panic);
        }
    }
}

use runne_application::ports::EventStoreError;
use runne_domain::id::{AttemptId, TaskRunId};

/// Whether a CurrentPermission cancellation recovery can complete durably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommandCancellationStopEvidence {
    /// A durable permission stop row exists whose reason is a valid
    /// cancellation-compatible stop observation (`1..=5`, exactly the set the
    /// live terminal validation accepts for `CancellationCompleted`).
    Proven,
    /// No stop row exists at all, and the fully validated binding plus the
    /// durable `CancellationRequested` event let the completion unit of work
    /// record the canonical cancellation stop itself.
    Recordable,
    /// The retained stop row carries reason `6` — the live terminal
    /// validation rejects it as cancellation proof, so recovery must neither
    /// overwrite the reason nor complete the cancellation through this
    /// pathway.
    ConflictingStop,
    /// No validated binding (or no `CancellationRequested` event): the
    /// completion unit of work cannot possibly prove the stop, so recovery
    /// must settle for the canonical unconfirmed state instead of a fabricated
    /// completion.
    Missing,
}

impl super::super::super::StoreTransaction {
    /// Pre-flight evidence check for the V68 cancellation recovery. It never
    /// weakens the completion unit of work; it only classifies the durable
    /// stop evidence so recovery can pick the honest branch: complete with
    /// strict proof, settle canonically unconfirmed, or surface the stop
    /// conflict as a categorized integrity failure.
    pub fn local_command_cancellation_stop_evidence(
        &self,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
    ) -> Result<LocalCommandCancellationStopEvidence, EventStoreError> {
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let digest = match super::cancel_support::verified_binding_digest(
            &reader,
            &taskrun_id,
            &attempt_id,
        )? {
            Some(digest) => digest,
            None => return Ok(LocalCommandCancellationStopEvidence::Missing),
        };
        match super::super::permission::stop::read_stop(
            &reader,
            taskrun_id.as_bytes(),
            attempt_id.as_bytes(),
            &digest,
        )? {
            Some(1..=5) => Ok(LocalCommandCancellationStopEvidence::Proven),
            Some(_) => Ok(LocalCommandCancellationStopEvidence::ConflictingStop),
            None => {
                if super::cancel_support::cancellation_stop_reference(&reader, taskrun_id)?
                    .is_some()
                {
                    Ok(LocalCommandCancellationStopEvidence::Recordable)
                } else {
                    Ok(LocalCommandCancellationStopEvidence::Missing)
                }
            }
        }
    }
}

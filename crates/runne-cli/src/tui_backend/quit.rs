use super::Backend;
use runne_runtime_client::{
    LocalExecutionOutcome, LocalStopEvidence, RemoteCancellationEvidence, RemoteEffectOutcome,
};
impl Backend {
    pub(super) async fn can_exit(&mut self) -> Result<(), String> {
        if self.owner.workspace_id.is_some() {
            self.recover_pending().await?;
        }
        let runs = self
            .owner
            .client
            .list_task_runs()
            .await
            .map_err(|error| format!("Cannot confirm safe runtime exit: {error}"))?;
        if self.submit_uncertain
            || runs
                .iter()
                .any(|run| !crate::is_terminal_state(run.state()))
        {
            return Err("Task still active or uncertain; cancel and await runtime confirmation before closing the owned runtime".into());
        }
        for run in runs {
            let effects = self
                .owner
                .client
                .get_task_run_effects(run.task_run_id())
                .await
                .map_err(|error| format!("Cannot confirm effect completion: {error}"))?;
            let local_pending = effects.local_command().is_some_and(|local| {
                matches!(
                    local.outcome(),
                    LocalExecutionOutcome::Running | LocalExecutionOutcome::OutcomeUnknown
                ) || matches!(
                    local.stop(),
                    LocalStopEvidence::Requested | LocalStopEvidence::Unconfirmed
                )
            });
            let remote_pending = remote_pending(
                effects.remote().outcome(),
                effects.remote().cancellation(),
                effects.cancellation_requested(),
            );
            if local_pending || remote_pending {
                return Err("An external effect is still active or uncertain; reconcile it before closing the owned runtime".into());
            }
        }
        Ok(())
    }
}

const fn remote_pending(
    outcome: RemoteEffectOutcome,
    cancellation: RemoteCancellationEvidence,
    requested: bool,
) -> bool {
    matches!(
        outcome,
        RemoteEffectOutcome::Running | RemoteEffectOutcome::Unknown
    ) || (requested
        && matches!(
            cancellation,
            RemoteCancellationEvidence::Requested
                | RemoteCancellationEvidence::Unconfirmed
                | RemoteCancellationEvidence::Unknown
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_already_terminal_allows_exit_but_unknown_stays_blocked() {
        assert!(!remote_pending(
            RemoteEffectOutcome::Completed,
            RemoteCancellationEvidence::AlreadyTerminal,
            true
        ));
        assert!(remote_pending(
            RemoteEffectOutcome::Unknown,
            RemoteCancellationEvidence::AlreadyTerminal,
            true
        ));
        assert!(remote_pending(
            RemoteEffectOutcome::Running,
            RemoteCancellationEvidence::AlreadyTerminal,
            true
        ));
        assert!(remote_pending(
            RemoteEffectOutcome::Completed,
            RemoteCancellationEvidence::Unconfirmed,
            true
        ));
    }
}

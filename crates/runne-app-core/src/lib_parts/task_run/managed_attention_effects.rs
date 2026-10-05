const MANAGED_ATTENTION_EFFECT_READ_LIMIT: usize = 64;
const MANAGED_ATTENTION_EFFECT_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(5);

struct ManagedAttentionEffects {
    uncertain_task_run_ids: Vec<CanonicalId>,
    complete: bool,
}

impl AppCore {
    async fn read_managed_attention_effects(
        &self,
        context: &RuntimeOperationContext,
        snapshots: &[runne_runtime_client::TaskRunSnapshot],
    ) -> ManagedAttentionEffects {
        let deadline = tokio::time::Instant::now() + MANAGED_ATTENTION_EFFECT_DEADLINE;
        let mut complete = snapshots.len() <= MANAGED_ATTENTION_EFFECT_READ_LIMIT;
        let mut uncertain_task_run_ids = Vec::new();

        for run in snapshots.iter().take(MANAGED_ATTENTION_EFFECT_READ_LIMIT) {
            let effects = tokio::time::timeout_at(
                deadline,
                context.client.get_task_run_effects(run.task_run_id()),
            )
            .await;
            if self.require_current_operation_context(context).is_err() {
                complete = false;
                break;
            }

            let Ok(Ok(effects)) = effects else {
                complete = false;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                continue;
            };
            if effects.task_run_id() != run.task_run_id()
                || effects.stream_version() != run.stream_version()
                || run
                    .active_attempt_id()
                    .is_some_and(|active_attempt| effects.attempt_id() != Some(active_attempt))
            {
                complete = false;
                continue;
            }
            if task_run_effects_require_attention(&effects) {
                uncertain_task_run_ids.push(run.task_run_id());
            }
        }

        ManagedAttentionEffects {
            uncertain_task_run_ids,
            complete,
        }
    }
}

fn task_run_effects_require_attention(
    effects: &runne_runtime_client::TaskRunEffectsV1,
) -> bool {
    use runne_runtime_client::{
        LocalExecutionOutcome, LocalStopEvidence, RemoteAccountingDisposition,
        RemoteCancellationEvidence, RemoteEffectAvailability, RemoteEffectOutcome,
        RemotePublicationDisposition,
    };

    let remote = effects.remote();
    let remote_uncertain = matches!(
        remote.outcome(),
        RemoteEffectOutcome::Unknown | RemoteEffectOutcome::Incomplete
    ) || remote.publication() == RemotePublicationDisposition::Unknown
        || remote.accounting() == RemoteAccountingDisposition::Unknown
        || matches!(
            remote.cancellation(),
            RemoteCancellationEvidence::Unconfirmed | RemoteCancellationEvidence::Unknown
        )
        || matches!(
            remote.availability(),
            RemoteEffectAvailability::Unavailable | RemoteEffectAvailability::Unknown
        );
    let local_uncertain = effects.local_command().is_some_and(|local| {
        local.outcome() == LocalExecutionOutcome::OutcomeUnknown
            || local.stop() == LocalStopEvidence::Unconfirmed
    });
    remote_uncertain || local_uncertain
}

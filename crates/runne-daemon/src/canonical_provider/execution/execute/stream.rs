use super::super::*;
use runne_application::provider::ProviderExecutionStore;
use runne_provider::{ProviderStreamId, ProviderStreamItem, ProviderTerminalPricing, StreamCursor};
use runne_runtime::provider_execution::{
    ProviderEventJournalContext, ProviderTerminalPersistence, RuntimeProviderExecution,
};
use runne_secure_store::ProviderJournalKeyring;
use std::time::Duration;

const CANCELLATION_POLL: Duration = Duration::from_millis(100);
const CANCEL_ACK_LIMIT: Duration = Duration::from_secs(2);

// These fields form one complete stream boundary with persistence and cancellation inputs.
#[allow(clippy::too_many_arguments)]
pub(super) async fn poll_next<K, S, P, C>(
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    adapter: &dyn CanonicalProviderEffect,
    stream_id: &ProviderStreamId,
    cursor: StreamCursor,
    context: &ProviderEventJournalContext,
    store: &dyn ProviderExecutionStore,
    collector: Option<&mut runne_runtime::provider_tool::CommittedToolProposalCollector>,
    deadline: Option<tokio::time::Instant>,
    mut cancelled: C,
) -> Result<
    (
        ProviderStreamItem,
        Option<runne_runtime::provider_tool::ProviderToolLoopOutcome>,
    ),
    CanonicalProviderExecutionError,
>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
    C: FnMut() -> bool,
{
    if collector.is_none() {
        let item = execution
            .next_and_commit(adapter, stream_id, cursor, context)
            .await
            .map_err(super::super::super::projection::map_execution_error)?;
        return Ok((item, None));
    }
    let deadline = deadline.ok_or(CanonicalProviderExecutionError::Unavailable)?;
    let poll = async {
        let Some(collector) = collector else {
            return Err(CanonicalProviderExecutionError::Unavailable);
        };
        let (item, outcome) = execution
            .next_and_commit_tool_aware(adapter, stream_id, cursor, context, collector)
            .await
            .map_err(super::super::super::projection::map_execution_error)?;
        Ok::<_, CanonicalProviderExecutionError>((item, outcome))
    };
    tokio::pin!(poll);
    let result = tokio::time::timeout_at(deadline, async {
        loop {
            tokio::select! {
                biased;
                result = &mut poll => return result,
                () = tokio::time::sleep(CANCELLATION_POLL) => {
                    if cancelled() {
                        freeze_and_cancel(store, adapter, stream_id, context).await;
                        return Err(CanonicalProviderExecutionError::Uncertain);
                    }
                }
            }
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            freeze_and_cancel(store, adapter, stream_id, context).await;
            Err(CanonicalProviderExecutionError::Uncertain)
        }
    }
}

pub(super) async fn freeze_and_cancel(
    store: &dyn ProviderExecutionStore,
    adapter: &dyn CanonicalProviderEffect,
    stream_id: &ProviderStreamId,
    context: &ProviderEventJournalContext,
) {
    let _ = store.mark_execution_uncertain(context.attempt_id, context.fencing_token);
    let _ = tokio::time::timeout(
        CANCEL_ACK_LIMIT,
        adapter.cancel(runne_provider::CancelRequest::new(*stream_id)),
    )
    .await;
}

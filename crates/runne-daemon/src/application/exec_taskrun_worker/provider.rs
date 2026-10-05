use super::logging::warn_lease_renewal_failure;
use super::*;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, TaskRunAssignmentIdentity,
    TaskRunAssignmentPort, TaskRunExecutionInputPort, TaskRunLeaseRenewal, TaskRunQueueCandidate,
    TextGenerationReceipt,
};
use runne_domain::id::CommandId;
use runne_domain::message::MessageText;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;
use std::sync::atomic::Ordering;

#[path = "provider/claimed.rs"]
mod claimed;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "provider/d2_cancellation.rs"]
mod d2_cancellation;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "provider/d2_loop.rs"]
mod d2_loop;
#[path = "provider/support.rs"]
mod support;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) use support::d2_stage;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
use support::provider_error_stage;
use support::{ClaimedProviderOutcome, begin_failure_proves_no_start, local_command_route};

impl DaemonAutomaticTaskRuns {
    pub(in crate::application) async fn execute_one(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<(), AutomaticTaskRunError> {
        if local_command_route(
            self.is_local_command_candidate(candidate)?,
            cfg!(all(feature = "desktop-protected", target_os = "linux")),
        )? {
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            return self
                .execute_local_candidate(candidate)
                .await
                .unwrap_or(Err(AutomaticTaskRunError::Uncertain));
            #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
            return Err(AutomaticTaskRunError::Unavailable);
        }
        self.execute_provider_candidate(candidate).await
    }
}

use super::*;

#[derive(Clone)]
pub(crate) struct D2ProviderRound {
    pub(crate) current_taskrun_head: u64,
    pub(crate) round_index: u32,
    pub(crate) previous_tool_result: Option<runne_application::ports::TaskRunProviderToolResultRef>,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(crate) continuation_target_fence: Option<
        crate::application::exec_taskrun_worker::tool_invocation::target_snapshot::D2TargetFence,
    >,
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct D2ToolTerminalRef {
    pub(crate) attempt_id: runne_provider::DispatchAttemptId,
    pub(crate) outbox_id: [u8; 16],
    pub(crate) terminal_sequence: u64,
    pub(crate) settlement_digest: [u8; 32],
    pub(crate) fencing_token: u64,
    pub(crate) call_digest_version: runne_provider::ProviderCallDigestVersion,
    pub(crate) profile_digest: [u8; 32],
    pub(crate) runtime_generation: u64,
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum D2ProviderRoundOutcome {
    Proposal {
        call: runne_runtime::provider_tool::RuntimeToolCall,
        sources: Vec<runne_store::store::taskrun_tool_invocation::ToolSourceRef>,
    },
    FinalStop {
        terminal: D2ToolTerminalRef,
        sources: Vec<runne_store::store::taskrun_tool_invocation::ToolSourceRef>,
    },
}

impl CanonicalProviderExecutionService for DaemonCanonicalProviderService {
    fn execute(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            match self.execute_internal(job, None, None, false, None).await? {
                InternalProviderResult::Text(receipt) => Ok(receipt),
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                InternalProviderResult::ToolRound(_) => {
                    Err(CanonicalProviderExecutionError::Uncertain)
                }
            }
        })
    }

    fn execute_claimed(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: runne_application::ports::TaskRunAssignmentIdentity,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            match self
                .execute_internal(job, Some(assignment), None, false, None)
                .await?
            {
                InternalProviderResult::Text(receipt) => Ok(receipt),
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                InternalProviderResult::ToolRound(_) => {
                    Err(CanonicalProviderExecutionError::Uncertain)
                }
            }
        })
    }
}

mod execute;
mod failure;
mod route;
pub(in crate::canonical_provider) use route::SecondaryProfileRoute;

pub(crate) enum InternalProviderResult {
    Text(runne_application::ports::TextGenerationReceipt),
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    ToolRound(D2ProviderRoundOutcome),
}

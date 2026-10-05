#[derive(Clone, Copy)]
pub(super) enum LocalWorkerMode {
    Provider,
    D2Pending,
    D2CrashPendingApproval,
    D2CrashApprovedBeforeLease,
    D2CrashClaimedBeforeArea,
    D2RestartStartedBeforeCycle,
    D2RestartCycleBeforeBudget,
    D2RestartContextCommitted,
    D2RestartCancelledBeforeBudget,
    D2RestartPlanCommitted,
    D2RestartProposalBeforeInvocation,
    D2RestartRemoteUnknown,
    D2ReadCreateStop,
    D2FinishBeforeCancel,
    D2CrashAfterResult,
    D2CrashBeforeGo,
    D2CrashAfterCreateEffect,
    D2StaleAfterRead,
    D2StaleAfterResult,
    D2StaleFinalTarget,
    D2OutsideTarget,
    D2ExcludedTarget,
    D2CancelFinalResponse,
    D2BudgetExhausted,
    D2DenyCreate,
    D2DenyRead,
    D2StaleApproval,
    D2ExpiredApproval,
    D2TrustRevokeBeforeLease,
    D2IncompleteProviderResponse,
    D2UnknownTool,
    D2MalformedArguments,
    D2EarlyFinalStop,
    D2TargetChangedBeforeGo,
    D2CancelBeforeGo,
    D2CancelAfterCreateEffect,
    D2CancelRestartAfterCreateEffect,
    D2TruncatedReadResult,
    Standard,
    Crash,
    CancelBeforeRelease,
    CancelAfterExit,
    CompleteAfterExit,
    RestartAfterMissingArea,
    RestartAfterDurableSuccess,
    RestartAfterDurableFailure,
    RestartAfterDurableCancel,
}

impl LocalWorkerMode {
    pub(super) fn is_d2(self) -> bool {
        matches!(
            self,
            Self::D2Pending
                | Self::D2CrashPendingApproval
                | Self::D2CrashApprovedBeforeLease
                | Self::D2CrashClaimedBeforeArea
                | Self::D2RestartStartedBeforeCycle
                | Self::D2RestartCycleBeforeBudget
                | Self::D2RestartContextCommitted
                | Self::D2RestartCancelledBeforeBudget
                | Self::D2RestartPlanCommitted
                | Self::D2RestartProposalBeforeInvocation
                | Self::D2RestartRemoteUnknown
                | Self::D2ReadCreateStop
                | Self::D2FinishBeforeCancel
                | Self::D2CrashAfterResult
                | Self::D2CrashBeforeGo
                | Self::D2CrashAfterCreateEffect
                | Self::D2StaleAfterRead
                | Self::D2StaleAfterResult
                | Self::D2StaleFinalTarget
                | Self::D2OutsideTarget
                | Self::D2ExcludedTarget
                | Self::D2CancelFinalResponse
                | Self::D2BudgetExhausted
                | Self::D2DenyCreate
                | Self::D2DenyRead
                | Self::D2StaleApproval
                | Self::D2ExpiredApproval
                | Self::D2TrustRevokeBeforeLease
                | Self::D2IncompleteProviderResponse
                | Self::D2UnknownTool
                | Self::D2MalformedArguments
                | Self::D2EarlyFinalStop
                | Self::D2TargetChangedBeforeGo
                | Self::D2CancelBeforeGo
                | Self::D2CancelAfterCreateEffect
                | Self::D2CancelRestartAfterCreateEffect
                | Self::D2TruncatedReadResult
        )
    }

    pub(super) const fn d2_scenario(self) -> Option<&'static str> {
        match self {
            Self::D2ReadCreateStop => Some("read-create-stop"),
            Self::D2FinishBeforeCancel => Some("finish-before-cancel"),
            Self::D2CrashAfterResult => Some("result-commit-crash"),
            Self::D2CrashPendingApproval => Some("crash-pending-approval"),
            Self::D2CrashApprovedBeforeLease => Some("crash-approved-before-lease"),
            Self::D2CrashClaimedBeforeArea => Some("crash-claimed-before-area"),
            Self::D2RestartStartedBeforeCycle => Some("restart-started-before-cycle"),
            Self::D2RestartCycleBeforeBudget => Some("restart-cycle-before-budget"),
            Self::D2RestartContextCommitted => Some("restart-context-committed"),
            Self::D2RestartCancelledBeforeBudget => Some("restart-cancelled-before-budget"),
            Self::D2RestartPlanCommitted => Some("restart-plan-committed"),
            Self::D2RestartProposalBeforeInvocation => Some("restart-proposal-before-invocation"),
            Self::D2RestartRemoteUnknown => Some("restart-dispatched-remote-unknown"),
            Self::D2CrashBeforeGo => Some("crash-before-go"),
            Self::D2CrashAfterCreateEffect => Some("crash-after-create-effect"),
            Self::D2StaleAfterRead => Some("stale-after-read"),
            Self::D2StaleAfterResult => Some("stale-after-result"),
            Self::D2StaleFinalTarget => Some("stale-final-target"),
            Self::D2OutsideTarget => Some("outside-target"),
            Self::D2ExcludedTarget => Some("excluded-target"),
            Self::D2CancelFinalResponse => Some("cancel-final-response"),
            Self::D2BudgetExhausted => Some("budget-exhausted"),
            Self::D2DenyCreate => Some("deny-create"),
            Self::D2DenyRead => Some("deny-read"),
            Self::D2StaleApproval => Some("stale-approval"),
            Self::D2ExpiredApproval => Some("approval-expiry"),
            Self::D2TrustRevokeBeforeLease => Some("revoke-before-lease"),
            Self::D2IncompleteProviderResponse => Some("incomplete-provider-response"),
            Self::D2UnknownTool => Some("unknown-tool-proposal"),
            Self::D2MalformedArguments => Some("malformed-tool-arguments"),
            Self::D2EarlyFinalStop => Some("early-final-stop"),
            Self::D2TargetChangedBeforeGo => Some("target-changed-before-go"),
            Self::D2CancelBeforeGo => Some("cancel-before-go"),
            Self::D2CancelAfterCreateEffect => Some("cancel-after-create-effect"),
            Self::D2CancelRestartAfterCreateEffect => Some("cancel-restart-after-create-effect"),
            Self::D2TruncatedReadResult => Some("truncated-read-result"),
            _ => None,
        }
    }

    pub(super) const fn d2_kill_stage(self) -> Option<&'static str> {
        match self {
            Self::D2RestartStartedBeforeCycle => Some("start_cycle"),
            Self::D2RestartCycleBeforeBudget => Some("cycle_started"),
            Self::D2RestartContextCommitted => Some("context_committed"),
            Self::D2RestartCancelledBeforeBudget => Some("cycle_started"),
            Self::D2RestartPlanCommitted => Some("plan_committed"),
            Self::D2RestartProposalBeforeInvocation => Some("proposal_received"),
            Self::D2RestartRemoteUnknown => Some("provider_uncertain"),
            _ => None,
        }
    }

    pub(super) const fn barrier_mode(self) -> Option<&'static str> {
        match self {
            Self::D2CrashApprovedBeforeLease | Self::D2TrustRevokeBeforeLease => {
                Some("approved-before-lease")
            }
            Self::D2CrashClaimedBeforeArea => Some("claimed-before-area"),
            Self::CancelBeforeRelease | Self::D2TargetChangedBeforeGo | Self::D2CancelBeforeGo => {
                Some("pre-release")
            }
            Self::D2StaleAfterRead
            | Self::D2CancelAfterCreateEffect
            | Self::D2CrashAfterCreateEffect
            | Self::D2CancelRestartAfterCreateEffect
            | Self::CancelAfterExit
            | Self::CompleteAfterExit => Some("after-exit"),
            Self::D2StaleAfterResult
            | Self::D2CrashAfterResult
            | Self::RestartAfterDurableSuccess
            | Self::RestartAfterDurableFailure
            | Self::RestartAfterDurableCancel => Some("after-terminal"),
            Self::D2CrashBeforeGo => Some("pre-release"),
            _ => None,
        }
    }
}

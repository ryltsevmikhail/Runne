struct CancellationFacts {
    terminal: Option<crate::ports::ProviderTerminalCancellationEvidence>,
    unknown_terminal: Option<crate::ports::ProviderUnknownTerminalCancellationEvidence>,
    remote_artifact: Option<crate::ports::ProviderRemoteArtifactCancellationEvidence>,
    pre_effect: Option<crate::ports::ProviderPreEffectCancellationEvidence>,
    no_admission: Option<crate::ports::ProviderNoAdmissionCancellationEvidence>,
    d2_tool_loop: Option<crate::ports::D2ToolLoopCancellationEvidence>,
    d2_restart: Option<crate::ports::D2ToolLoopRestartEvidence>,
    taskrun_version: Option<u64>,
}

impl CancellationFacts {
    fn from_completion(completion: &ConversationTextCompletion) -> Self {
        let terminal = match completion {
            ConversationTextCompletion::TerminalSettledCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let unknown_terminal = match completion {
            ConversationTextCompletion::UnknownJournalSettledCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let remote_artifact = match completion {
            ConversationTextCompletion::RemoteArtifactSettledCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let pre_effect = match completion {
            ConversationTextCompletion::PreEffectRejectedCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let no_admission = match completion {
            ConversationTextCompletion::NoProviderAdmissionCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let d2_tool_loop = match completion {
            ConversationTextCompletion::D2ToolLoopCancellation { evidence } => Some(*evidence),
            _ => None,
        };
        let d2_restart = match completion {
            ConversationTextCompletion::D2ToolLoopRestart { evidence } => Some(evidence.clone()),
            _ => None,
        };
        let taskrun_version = terminal
            .map(|evidence| evidence.cancellation_taskrun_version)
            .or_else(|| unknown_terminal.map(|evidence| evidence.cancellation_taskrun_version))
            .or_else(|| remote_artifact.map(|evidence| evidence.cancellation_taskrun_version()))
            .or_else(|| pre_effect.map(|evidence| evidence.cancellation_taskrun_version))
            .or_else(|| no_admission.map(|evidence| evidence.cancellation_taskrun_version))
            .or_else(|| d2_tool_loop.map(|evidence| evidence.cancellation_taskrun_version))
            .or_else(|| d2_restart.as_ref().map(|evidence| evidence.expected_taskrun_head));
        Self {
            terminal,
            unknown_terminal,
            remote_artifact,
            pre_effect,
            no_admission,
            d2_tool_loop,
            d2_restart,
            taskrun_version,
        }
    }
}

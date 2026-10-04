use super::super::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob, DaemonCanonicalProviderService,
};

impl DaemonCanonicalProviderService {
    pub(super) fn finish_remote_terminal_failure(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>
    {
        self.conversation_service
            .finish_text(
                &job.context,
                runne_application::commands::FinishConversationTextInput {
                    started: job.started,
                    original: job.original,
                    completion: runne_application::commands::ConversationTextCompletion::Rejected {
                        reason: runne_domain::conversation::GenerationFailureReason::ProviderExecutionFailed,
                    },
                },
            )
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)
    }
}

use super::*;

impl ProviderTerminalPersistence for DaemonProviderRuntimeStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.terminal.commit_terminal(request)
    }

    fn commit_unknown_terminal(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn ProviderUnknownTerminalAuthenticator,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        self.terminal
            .commit_unknown_terminal(selector, authenticate)
    }

    fn replay_unknown_terminal(
        &self,
        selector: &ProviderTerminalUnknownSelector,
        authenticate: &dyn ProviderUnknownTerminalAuthenticator,
    ) -> Result<Option<ProviderTerminalCommitOutcome>, ProviderExecutionError> {
        self.terminal
            .replay_unknown_terminal(selector, authenticate)
    }
}

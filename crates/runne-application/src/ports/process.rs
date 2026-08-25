use runne_api::{
    ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessOutputPage,
    ProcessQueryContext, ProcessSnapshot, StartProcessCommand,
};
use runne_domain::id::ProcessId;

/// Runtime-owned provider for process lifecycle and sanitized output.
pub trait ProcessProvider: Clone + Send + Sync + 'static {
    fn start_process(
        &self,
        context: &ProcessCommandContext,
        command: &StartProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError>;
    fn get_process(
        &self,
        context: &ProcessQueryContext,
        process_id: ProcessId,
    ) -> Result<ProcessSnapshot, ProcessHostError>;
    fn read_process_output(
        &self,
        context: &ProcessQueryContext,
        process_id: ProcessId,
        after_sequence: u64,
        limit: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError>;
    fn stop_process(
        &self,
        context: &ProcessCommandContext,
        command: &ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError>;
}

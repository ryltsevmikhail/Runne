//! Fail-closed process provider until a protected native backend is qualified.

use runne_api::{
    ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessOutputPage,
    ProcessQueryContext, ProcessSnapshot, StartProcessCommand,
};
use runne_application::ports::ProcessProvider;
use runne_domain::id::ProcessId;

#[derive(Clone, Copy)]
pub(super) struct UnavailableProcessProvider;

impl ProcessProvider for UnavailableProcessProvider {
    fn start_process(
        &self,
        _: &ProcessCommandContext,
        _: &StartProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    fn get_process(
        &self,
        _: &ProcessQueryContext,
        _: ProcessId,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    fn read_process_output(
        &self,
        _: &ProcessQueryContext,
        _: ProcessId,
        _: u64,
        _: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    fn stop_process(
        &self,
        _: &ProcessCommandContext,
        _: &ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
}

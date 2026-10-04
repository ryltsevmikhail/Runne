use std::sync::Arc;

use super::{RuntimeTaskExit, WorkerRegistry};
use crate::error::RuntimeError;
use crate::types::Reply;
use runne_application::commands::SupersedeUnknownTaskRunInput;
use runne_application::ports::{ApplicationCommandContext, EventStore, IdGenerator, UnitOfWork};
use runne_application::service::TaskRunService;

impl<E, U, I> WorkerRegistry<E, U, I>
where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    pub(super) fn spawn_supersede_unknown_task(
        &mut self,
        context: ApplicationCommandContext,
        input: SupersedeUnknownTaskRunInput,
        service: Arc<TaskRunService<E, U, I>>,
        reply: Reply,
    ) {
        self.join_set.spawn(async move {
            let outcome = service
                .supersede_unknown_task_run(&context, input)
                .map(|result| {
                    runne_application::commands::CommandOutcome::UnknownSuccessorCreated {
                        predecessor_taskrun_id: result.predecessor_taskrun_id,
                        predecessor_version: result.predecessor_version,
                        conversation_id: result.conversation_id,
                        conversation_version: result.conversation_version,
                        successor_taskrun_id: result.successor_taskrun_id,
                        successor_version: result.successor_version,
                    }
                })
                .map_err(RuntimeError::Application);
            RuntimeTaskExit::Submit { outcome, reply }
        });
    }
}

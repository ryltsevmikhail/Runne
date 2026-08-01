impl<E> TaskRunQueryHostPort for RuntimeTaskRunHost<E>
where
    E: EventStore + Clone + Send + Sync + 'static,
{
    async fn get_task_run(
        &self,
        taskrun_id: gocode_domain::id::TaskRunId,
    ) -> Result<TaskRunSnapshot, TaskRunHostError> {
        let event_store = self.event_store.clone();
        tokio::task::spawn_blocking(move || {
            let stream = event_store
                .load_task_run(taskrun_id)
                .map_err(map_event_store_error)?;
            let last = stream.events.last().ok_or(TaskRunHostError::Unavailable)?;
            if last.sequence() != stream.current_version
                || Some(*last.event_id()) != stream.last_event_id
            {
                return Err(TaskRunHostError::Unavailable);
            }

            let aggregate =
                TaskRun::replay(&stream.events).map_err(|_| TaskRunHostError::Unavailable)?;
            Ok(TaskRunSnapshot {
                taskrun_id,
                state: state_to_canonical(aggregate.state()),
                stream_version: stream.current_version,
                active_attempt_id: aggregate.active_attempt().copied(),
                terminal_result: aggregate
                    .terminal_result()
                    .cloned()
                    .map(terminal_result_to_canonical),
            })
        })
        .await
        .map_err(|_| TaskRunHostError::Unavailable)?
    }
}

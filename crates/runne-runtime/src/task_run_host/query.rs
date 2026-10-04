impl<E> TaskRunQueryHostPort for RuntimeTaskRunHost<E>
where
    E: EventStore + Clone + Send + Sync + 'static,
{
    async fn get_task_run(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
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
                conversation_id: aggregate.conversation_id().copied(),
                workspace_id: aggregate.workspace_id().copied(),
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

    async fn list_task_runs(&self) -> Result<Vec<TaskRunSnapshot>, TaskRunHostError> {
        let event_store = self.event_store.clone();
        tokio::task::spawn_blocking(move || {
            let task_run_ids = event_store
                .list_task_runs()
                .map_err(map_event_store_error)?;
            task_run_ids
                .into_iter()
                .map(|taskrun_id| {
                    let stream = event_store
                        .load_task_run(taskrun_id)
                        .map_err(map_event_store_error)?;
                    let last = stream.events.last().ok_or(TaskRunHostError::Unavailable)?;
                    if last.sequence() != stream.current_version
                        || Some(*last.event_id()) != stream.last_event_id
                    {
                        return Err(TaskRunHostError::Unavailable);
                    }
                    let aggregate = TaskRun::replay(&stream.events)
                        .map_err(|_| TaskRunHostError::Unavailable)?;
                    Ok(TaskRunSnapshot {
                        taskrun_id,
                        conversation_id: aggregate.conversation_id().copied(),
                        workspace_id: aggregate.workspace_id().copied(),
                        state: state_to_canonical(aggregate.state()),
                        stream_version: stream.current_version,
                        active_attempt_id: aggregate.active_attempt().copied(),
                        terminal_result: aggregate
                            .terminal_result()
                            .cloned()
                            .map(terminal_result_to_canonical),
                    })
                })
                .collect()
        })
        .await
        .map_err(|_| TaskRunHostError::Unavailable)?
    }

    async fn get_task_run_effects(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<runne_api::TaskRunEffectsV1, TaskRunHostError> {
        let event_store = self.event_store.clone();
        let effects_enricher = self.effects_enricher.clone();
        tokio::task::spawn_blocking(move || {
            let authenticator = effects_enricher
                .as_ref()
                .and_then(|enricher| enricher.remote_fact_authenticator());
            let source1_authenticator = effects_enricher
                .as_ref()
                .and_then(|enricher| enricher.unknown_terminal_fact_authenticator());
            let resolver = effects_enricher
                .as_ref()
                .and_then(|enricher| enricher.historical_model_resolver());
            let snapshot = event_store
                .load_task_run_effects_with_fact_authenticators(
                    taskrun_id,
                    authenticator.as_deref(),
                    source1_authenticator.as_deref(),
                    resolver.as_deref(),
                )
                .map_err(map_event_store_error)?;
            let mut effects = snapshot.effects.clone();
            if effects.taskrun_id != taskrun_id {
                return Err(TaskRunHostError::Unavailable);
            }
            if effects.local_command.is_some() {
                return Ok(effects);
            }
            if let Some(remote) = snapshot.remote.as_ref() {
                if effects.attempt_id != Some(remote.binding.taskrun_attempt_id)
                    || remote.binding.taskrun_id != taskrun_id
                {
                    return Err(TaskRunHostError::Unavailable);
                }
                let metadata = effects_enricher
                    .as_ref()
                    .map(|enricher| enricher.runtime_metadata(&snapshot))
                    .transpose()?
                    .flatten();
                let (availability, capabilities) = metadata.unwrap_or({
                    (
                        runne_api::RemoteEffectAvailabilityV1::Unavailable,
                        runne_api::RemoteEffectCapabilitiesV1 {
                            status_check: false,
                            stream_resume: false,
                            remote_cancel: false,
                        },
                    )
                });
                effects.remote.availability = availability;
                effects.remote.capabilities = capabilities;
            }
            Ok(effects)
        })
        .await
        .map_err(|_| TaskRunHostError::Unavailable)?
    }
}

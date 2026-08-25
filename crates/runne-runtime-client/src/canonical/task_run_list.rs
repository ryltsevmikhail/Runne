const MAX_TASK_RUN_LIST_ITEMS: usize = 4_096;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRunListWire {
    task_runs: Vec<TaskRunSnapshotWire>,
}

fn decode_task_run_list(wire: TaskRunListWire) -> Result<Vec<TaskRunSnapshot>, RuntimeApiError> {
    if wire.task_runs.len() > MAX_TASK_RUN_LIST_ITEMS {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::ResponseTooLarge));
    }
    wire.task_runs
        .into_iter()
        .map(TaskRunSnapshot::try_from)
        .collect()
}

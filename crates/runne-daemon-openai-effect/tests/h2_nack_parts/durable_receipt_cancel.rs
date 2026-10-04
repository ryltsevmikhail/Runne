fn cancel_task_run_publicly(
    database_path: &Path,
    identity: MainDatabaseIdentity,
    authority: RuntimeAuthorityId,
    taskrun_id: TaskRunId,
) {
    let guard: std::sync::Arc<dyn ProhibitedContentPort> = std::sync::Arc::new(AllowContent);
    let store = StoreTransaction::open_with_connections(
        database_path.to_str().expect("database path"),
        open_validated_connection(database_path, identity).expect("cancel writer"),
        open_validated_reader(database_path, identity).expect("cancel reader"),
        authority.clone(),
        guard,
    )
    .expect("public cancellation store");
    let version = store
        .load_task_run(taskrun_id)
        .expect("persisted TaskRun before cancellation")
        .current_version;
    runne_application::service::TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority,
    )
    .cancel_task_run(
        &context(0x39, "background-create-public-cancel"),
        runne_application::commands::CancelTaskRunInput {
            taskrun_id,
            expected_version: version,
        },
    )
    .expect("public TaskRun cancellation commits");
}

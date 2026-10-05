pub(crate) fn invocation_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> usize {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only invocation view");
    connection
        .query_row(
            "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [id.as_slice()],
            |row| row.get(0),
        )
        .expect("read invocation count")
}

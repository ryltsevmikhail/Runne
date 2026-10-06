use super::{finish_then_cancel, verify};

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    version: u64,
    read_watch: &std::fs::File,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    verify::assert_request_counts(runtime_root);
    verify::assert_encrypted_results(database, task, 2);
    verify::assert_conversation_receipt(client, conversation, task, database, runtime_root).await;
    if std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() == Ok("finish-before-cancel") {
        finish_then_cancel::exercise(
            client,
            task,
            conversation,
            version,
            read_watch,
            create_watch,
            database,
            runtime_root,
        )
        .await;
        return;
    }
    assert_eq!(
        super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        1,
        "auto-admitted read opened once with no replay effect"
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0,
        "duplicate approval caused no second create"
    );
    println!("PASS: D2 read/create results and three validated provider rounds task={task}");
}

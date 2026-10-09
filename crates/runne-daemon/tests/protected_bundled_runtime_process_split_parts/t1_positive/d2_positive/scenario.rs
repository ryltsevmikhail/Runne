use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn dispatch(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    read_path: &std::path::Path,
    create_path: &std::path::Path,
    watch: &std::fs::File,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
    create_approval: &Option<runne_runtime_client::ApprovalSummaryDto>,
) -> bool {
    if let Some(create_approval) = create_approval.as_ref() {
        approval::approve_twice(client, create_approval, "create").await;
        let unlaunched_barrier = match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
            Ok("crash-approved-before-lease") => Some(("approved-before-lease", "approved")),
            Ok("crash-claimed-before-area") => Some(("claimed-before-area", "claimed")),
            _ => None,
        };
        if let Some((barrier, state)) = unlaunched_barrier {
            crash::before_unlaunched(
                Some(barrier),
                state,
                2,
                supervisor,
                executable,
                session_bus_socket,
                runtime_root,
                database,
                task,
                read_path,
                watch,
            )
            .await;
            return true;
        }
        match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
            Ok("crash-before-go") => {
                crash::before_receipt(
                    "pre-release",
                    supervisor,
                    executable,
                    session_bus_socket,
                    runtime_root,
                    database,
                    task,
                    create_path,
                    create_watch,
                    libc::IN_CREATE,
                    0,
                    0,
                    None,
                )
                .await;
                return true;
            }
            Ok("crash-after-create-effect") => {
                crash::before_receipt(
                    "after-exit",
                    supervisor,
                    executable,
                    session_bus_socket,
                    runtime_root,
                    database,
                    task,
                    create_path,
                    create_watch,
                    libc::IN_CREATE,
                    1,
                    1,
                    Some(CREATE_BYTES),
                )
                .await;
                return true;
            }
            _ => {}
        }
    }
    verify::wait_results(client, database, task, 2, runtime_root).await;
    assert_eq!(
        std::fs::read(create_path).expect("native create result"),
        CREATE_BYTES
    );
    assert_eq!(
        count_watch_mask(create_watch, libc::IN_CREATE),
        1,
        "one native create emitted one IN_CREATE event"
    );
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);
    if super::super::super::managed_ask::enabled() {
        super::super::super::managed_ask::assert_human_create_admission(
            client,
            database,
            task,
            workspace_id,
            create_approval
                .as_ref()
                .expect("managed Ask create requires human approval"),
        )
        .await;
    }

    if after_results::dispatch(after_results::Fixture {
        client,
        task,
        conversation: conversation_id,
        read_path,
        create_path,
        read_watch: watch,
        create_watch,
        database,
        runtime_root,
        supervisor,
        executable,
        session_bus_socket,
    })
    .await
    {
        return true;
    }
    false
}

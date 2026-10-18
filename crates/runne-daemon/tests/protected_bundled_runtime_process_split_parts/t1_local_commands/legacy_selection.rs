use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture uses the real runtime, workspace, database, and same-root restart handles."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
) {
    eprintln!("RUN: legacy V1 current-route selection rejects before local effect");
    let initial = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read default permission mode before legacy selection seed");
    assert_eq!(
        initial.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(initial.authorization_revision, 0);

    let listener = LoopbackCapture::new();
    let tag = format!("local-legacy-selection-{}", uuid::Uuid::now_v7());
    let effect = project_directory.join(format!("{tag}-effect"));
    let script = format!(
        "printf 'effect\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'legacy\\n' >&3; exec 3>&-",
        shell_quote_path(&effect),
        listener.port
    );
    let request = local_submit(conversation_id, workspace_id, &tag, &script);
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit one structured local command against seeded V1 selection")
        .task_run_id();

    let terminal = wait_for_terminal(client, database, task, &effect, &effect).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    assert_eq!(
        super::super::super::t1_startup_diagnostic::local_preapproval_diagnostic(runtime_root),
        "current_legacy_identity_rejected"
    );
    assert_eq!(
        client
            .get_task_run_effects(task)
            .await
            .expect("read failed legacy-selection TaskRun effects")
            .local_command()
            .expect("public local command remains explicitly not started")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert!(!effect.exists());
    assert_no_task_approval(client, task).await;
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("read exact no-effect terminal release receipt"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0)
    );
    assert_eq!(
        local_precapture_authority_facts(database, task)
            .expect("read empty local permission authority facts"),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!(
        claim_count(database, task).expect("read exact claim count"),
        1
    );
    assert_eq!(
        local_route_facts(database, task).expect("read current local route"),
        (1, 2, 3)
    );

    let seeded = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read canonically seeded V1 selection");
    assert_eq!(seeded.selected_mode, runne_api::PermissionModeV1::RiskBased);
    assert_eq!(seeded.authorization_revision, 1);
    assert!(
        canonical_legacy_receipt(database, workspace_id)
            .expect("read legacy V1 receipt and extension facts"),
        "the current selection joins its matching V1 receipt without V2 extensions"
    );

    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay identical legacy-selection request before reopen");
    assert_eq!(replay.task_run_id(), task);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let reread = client
        .get_task_run(task)
        .await
        .expect("read terminal legacy-selection TaskRun after replay");
    assert_eq!(reread.state(), terminal.state());
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(reread.terminal_result(), terminal.terminal_result());
    assert!(!effect.exists());
    assert_eq!(claim_count(database, task).expect("re-read claim count"), 1);
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("re-read no-effect receipt after replay"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0)
    );
    assert_no_task_approval(client, task).await;

    supervisor
        .stop()
        .expect("gracefully stop same-root legacy-selection runtime");
    let (mut reopened, reopened_client) = super::super::super::t1_positive::restart_same_root(
        executable,
        session_bus_socket,
        runtime_root,
    )
    .await;
    let persisted = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read seeded Risk Based selection after same-root reopen");
    assert_eq!(
        persisted.selected_mode,
        runne_api::PermissionModeV1::RiskBased
    );
    assert_eq!(persisted.authorization_revision, 1);
    assert!(
        canonical_legacy_receipt(database, workspace_id)
            .expect("re-read legacy V1 receipt and extension facts after reopen"),
        "same-root reopen retains the V1 receipt without V2 extensions"
    );
    let reopened_replay = reopened_client
        .submit_task_run(request)
        .await
        .expect("replay identical legacy-selection request after reopen");
    assert_eq!(reopened_replay.task_run_id(), task);
    let reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read terminal legacy-selection TaskRun after reopen");
    assert_eq!(reopened_task.state(), terminal.state());
    assert_eq!(reopened_task.stream_version(), terminal.stream_version());
    assert_eq!(reopened_task.terminal_result(), terminal.terminal_result());
    assert!(!effect.exists());
    assert_eq!(
        claim_count(database, task).expect("re-read claim count after reopen"),
        1
    );
    assert_eq!(
        local_no_effect_release_facts(database, task)
            .expect("re-read no-effect receipt after reopen"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0)
    );
    assert_no_task_approval(&reopened_client, task).await;
    reopened
        .stop()
        .expect("stop reopened same-root legacy-selection runtime");
    assert!(
        listener.finish().is_empty(),
        "rejection and duplicate replay produced no accepted loopback connection"
    );
}

fn claim_count(database: &Path, task: runne_runtime_client::CanonicalId) -> rusqlite::Result<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

fn local_route_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<(i64, i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id = uuid::Uuid::parse_str(&task.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT COUNT(*),COALESCE(MAX(route),0),COALESCE(MAX(provenance),0)
           FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
        [id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
}

fn canonical_legacy_receipt(
    database: &Path,
    workspace: runne_runtime_client::CanonicalId,
) -> rusqlite::Result<bool> {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let id =
        uuid::Uuid::parse_str(&workspace.to_string()).map_err(|_| rusqlite::Error::InvalidQuery)?;
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM permission_mode_selections s
             JOIN permission_mode_command_receipts r
               ON r.command_id=s.last_command_id
              AND r.runtime_authority_id=s.runtime_authority_id
              AND r.principal_id=s.principal_id
              AND r.workspace_id=s.workspace_id
              AND r.project_id=s.project_id
              AND r.intent_digest=s.intent_digest
              AND r.selected_mode=s.selected_mode
              AND r.preset_version=s.preset_version
              AND r.authorization_revision=s.authorization_revision
              AND r.managed_policy_version=s.managed_policy_version
              AND r.managed_policy_digest=s.managed_policy_digest
              AND r.expires_at_unix_ms IS s.expires_at_unix_ms
             WHERE s.workspace_id=?1 AND s.selected_mode=2 AND s.preset_version=1
               AND s.authorization_revision=1
               AND NOT EXISTS(
                   SELECT 1 FROM permission_mode_command_receipt_managed_identity x
                    WHERE x.command_id=s.last_command_id
               )
               AND NOT EXISTS(
                   SELECT 1 FROM permission_mode_native_challenges c
                    WHERE c.command_id=s.last_command_id
               )
               AND NOT EXISTS(
                   SELECT 1 FROM permission_mode_native_challenge_managed_identity x
                   JOIN permission_mode_native_challenges c USING(challenge_id)
                    WHERE c.command_id=s.last_command_id
               )
         )",
        [id.as_bytes().as_slice()],
        |row| row.get(0),
    )
}

use super::*;

const CREATE_ARGS: &[u8] = br#"{"content_base64":"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK","path":"fixture-created.txt"}"#;

pub(in crate::t1_positive) fn assert_retained_sidecar(database: &Path) {
    if enabled() {
        let expected = *POLICY
            .get()
            .expect("managed Ask policy was seeded after trust");
        assert_eq!(
            read_policy(
                database,
                ProjectTrustProjectId::from_bytes(expected.project_id)
            ),
            expected
        );
    }
}

pub(in crate::t1_positive) fn assert_pending_create_no_release(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    assert!(approval.requires_decision());
    assert_eq!(approval.task_run_id(), task);
    let connection = read_only(database);
    let task_id = id_bytes(task);
    let approval_id = id_bytes(approval.approval_id());
    let (state, release, saved_approval): (String, bool, Vec<u8>) = connection
        .query_row(
            "SELECT state,release_started,approval_id FROM taskrun_tool_invocations
             WHERE taskrun_id=?1 AND tool_name='workspace.file.create_new'",
            [task_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read exact pending create invocation");
    assert_eq!(state, "proposed");
    assert!(!release, "pending create has no native release intent");
    assert_eq!(saved_approval.as_slice(), approval_id.as_slice());
}

pub(in crate::t1_positive) async fn assert_human_create_admission(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    task: runne_runtime_client::CanonicalId,
    workspace: runne_runtime_client::CanonicalId,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let approved = client
        .get_approval(approval.approval_id())
        .await
        .expect("read exact create approval after duplicate decision");
    assert_eq!(approved.task_run_id(), task);
    assert_eq!(approved.action(), "workspace.tool.invoke");
    assert!(approved.resource().contains("fixture-created.txt"));
    assert_eq!(approved.action_digest(), approval.action_digest());
    assert_eq!(
        approved.request_version(),
        approval.request_version() + 1,
        "duplicate approval leaves exactly one request-version transition"
    );
    assert_eq!(approved.policy_revision(), approval.policy_revision());
    assert_eq!(
        approved.state(),
        runne_runtime_client::ApprovalStateDto::Approved
    );

    let expected = *POLICY.get().expect("managed Ask policy was seeded");
    let mode = match std::env::var("RUNNE_TEST_D2_PERMISSION_MODE").as_deref() {
        Ok("ask_always") => 1,
        Ok("risk_based") => 2,
        Ok("full_access") => 3,
        _ => panic!("managed Ask child has an explicit supported preset"),
    };
    let connection = read_only(database);
    let mode_selection_digest =
        runne_application::permission_modes::managed_policy_semantics_digest(
            ProjectTrustProjectId::from_bytes(expected.project_id),
            expected.snapshot.record,
        );
    let task_id = id_bytes(task);
    let workspace_id = id_bytes(workspace);
    let approval_id = id_bytes(approval.approval_id());
    let creates: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_invocations
             WHERE taskrun_id=?1 AND tool_name='workspace.file.create_new'",
            [task_id.as_slice()],
            |row| row.get(0),
        )
        .expect("count exact TaskRun create proposals");
    assert_eq!(creates, 1);
    let row = connection
        .query_row(
            "SELECT i.state,i.attempt_id,i.call_id,i.tool_name,i.target_name,
                    i.arguments_digest,i.approval_id,i.approval_digest,i.policy_revision,
                    p.workspace_id,p.selected_mode,p.authorization_revision,
                    p.managed_policy_version,p.managed_policy_digest,p.decision_source,
                    p.relevant_policy_digest,s.project_id,s.authorization_revision,
                    s.managed_policy_version,s.managed_policy_digest
             FROM taskrun_tool_invocations i
             JOIN taskrun_tool_permission_admissions p
               USING(taskrun_id,attempt_id,cycle_id,proposal_index)
             JOIN permission_mode_selections s
               ON s.runtime_authority_id=p.runtime_authority_id
              AND s.principal_id=p.principal_id AND s.workspace_id=p.workspace_id
             WHERE i.taskrun_id=?1 AND i.approval_id=?2
               AND i.tool_name='workspace.file.create_new'",
            params![task_id.as_slice(), approval_id.as_slice()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, Vec<u8>>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, i64>(10)?,
                    r.get::<_, i64>(11)?,
                    r.get::<_, i64>(12)?,
                    r.get::<_, Vec<u8>>(13)?,
                    r.get::<_, i64>(14)?,
                    r.get::<_, Vec<u8>>(15)?,
                    r.get::<_, Vec<u8>>(16)?,
                    r.get::<_, i64>(17)?,
                    r.get::<_, i64>(18)?,
                    r.get::<_, Vec<u8>>(19)?,
                ))
            },
        )
        .expect("join exact create, Human admission, and selected mode");
    use sha2::Digest as _;
    let expected_attempt = id_bytes(approved.attempt_id().expect("approved invocation attempt"));
    assert_eq!(row.0, "result");
    assert_eq!(row.1.as_slice(), expected_attempt.as_slice());
    assert_eq!(row.2, "call_d2_create");
    assert_eq!(row.3, "workspace.file.create_new");
    assert_eq!(row.4, "fixture-created.txt");
    assert_eq!(
        row.5.as_slice(),
        sha2::Sha256::digest(CREATE_ARGS).as_slice()
    );
    assert_eq!(row.6.as_slice(), approval_id.as_slice());
    assert_eq!(row.7.as_slice(), approved.action_digest().as_slice());
    assert_eq!(row.8 as u64, approved.policy_revision());
    assert_eq!(row.9.as_slice(), workspace_id.as_slice());
    assert_eq!(row.10, mode);
    assert!(row.11 > 0);
    assert_eq!(row.11, row.17);
    assert_eq!(row.12 as u64, expected.snapshot.record.revision);
    assert_eq!(row.13.as_slice(), mode_selection_digest.as_bytes());
    assert_eq!(row.14, 1, "managed Ask requires Human admission");
    assert_eq!(row.15.as_slice(), expected.digest.as_slice());
    assert_eq!(row.16.as_slice(), expected.project_id.as_slice());
    assert_eq!(row.18 as u64, expected.snapshot.record.revision);
    assert_eq!(row.19.as_slice(), mode_selection_digest.as_bytes());
}

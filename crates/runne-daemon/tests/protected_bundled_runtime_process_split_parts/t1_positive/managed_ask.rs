use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ProjectTrustEffectPolicySnapshot,
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
    managed_effect_policy_digest_v2,
};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{path::Path, path::PathBuf, sync::OnceLock};

const CREATE_ARGS: &[u8] = br#"{"content_base64":"Y3JlYXRlZCB0aHJvdWdoIGFwcHJvdmVkIHRvb2wK","path":"fixture-created.txt"}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagedPolicy {
    project_id: [u8; 16],
    authority_id: [u8; 16],
    schema_version: i64,
    snapshot: ProjectTrustEffectPolicySnapshot,
    digest: [u8; 32],
}

static POLICY: OnceLock<ManagedPolicy> = OnceLock::new();
static TASK: OnceLock<[u8; 16]> = OnceLock::new();
static CREATE_WATCH: OnceLock<std::fs::File> = OnceLock::new();

pub(super) fn enabled() -> bool {
    std::env::var("RUNNE_TEST_D2_MANAGED_ASK").as_deref() == Ok("1")
}

pub(super) fn seed_after_trust(
    database: &Path,
    runtime_project_id: runne_runtime_client::CanonicalId,
) {
    if !enabled() {
        return;
    }
    let project = ProjectTrustProjectId::from_bytes(id_bytes(runtime_project_id));
    let before = read_policy(database, project);
    assert_eq!(before.snapshot.record.status, ProjectTrustStatus::Trusted);
    assert!(before.snapshot.record.revision > 0);
    assert_eq!(before.snapshot.record.managed_deny_mask, 0);
    assert_eq!(before.snapshot.policy.version, 1);
    assert_eq!(
        before.snapshot.policy.decisions(),
        [ManagedEffectDecision::Allow; 6],
        "public trust grant seeded the default six-class policy"
    );
    let mut connection = Connection::open(sidecar_path(database)).expect("open exact T1 sidecar");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin fixture-only policy seed");
    let changed = transaction
        .execute(
            "UPDATE managed_effect_policies SET fs_create=1
             WHERE project_id=?1 AND policy_version=1 AND fs_read=0 AND fs_create=0
               AND fs_write=0 AND fs_delete=0 AND process_start=0 AND network_use=0",
            [before.project_id.as_slice()],
        )
        .expect("seed only this fixture project's fs_create Ask rule");
    assert_eq!(changed, 1, "update exactly one existing policy row");
    let policies: i64 = transaction
        .query_row("SELECT COUNT(*) FROM managed_effect_policies", [], |row| {
            row.get(0)
        })
        .expect("count exact sidecar policy rows");
    assert_eq!(policies, 1);
    transaction
        .commit()
        .expect("commit fixture-only policy seed");
    let after = read_policy(database, project);
    assert_eq!(after.project_id, before.project_id);
    assert_eq!(after.authority_id, before.authority_id);
    assert_eq!(after.schema_version, before.schema_version);
    assert_eq!(after.snapshot.record, before.snapshot.record);
    assert_eq!(after.snapshot.policy.version, 1);
    assert_eq!(
        after
            .snapshot
            .policy
            .decision_for(ManagedEffectClass::FsCreate),
        ManagedEffectDecision::Ask
    );
    for class in [
        ManagedEffectClass::FsRead,
        ManagedEffectClass::FsWrite,
        ManagedEffectClass::FsDelete,
        ManagedEffectClass::ProcessStart,
        ManagedEffectClass::NetworkUse,
    ] {
        assert_eq!(
            after.snapshot.policy.decision_for(class),
            ManagedEffectDecision::Allow
        );
    }
    POLICY
        .set(after)
        .unwrap_or_else(|_| panic!("managed Ask seed ran more than once"));
}

pub(super) fn record_task(task: runne_runtime_client::CanonicalId) {
    if enabled() {
        TASK.set(id_bytes(task))
            .unwrap_or_else(|_| panic!("managed Ask child submitted multiple TaskRuns"));
    }
}

pub(super) fn record_create_watch(watch: &std::fs::File) {
    if enabled() {
        CREATE_WATCH
            .set(watch.try_clone().expect("clone create event watch"))
            .unwrap_or_else(|_| panic!("managed Ask create watch was recorded twice"));
    }
}

pub(super) fn task_id() -> runne_runtime_client::CanonicalId {
    id_from_bytes(*TASK.get().expect("managed Ask TaskRun was recorded"))
}

pub(super) fn create_watch() -> &'static std::fs::File {
    CREATE_WATCH
        .get()
        .expect("managed Ask create watch was recorded")
}

pub(super) fn assert_retained_sidecar(database: &Path) {
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

pub(super) fn assert_pending_create_no_release(
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

pub(super) async fn assert_human_create_admission(
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

fn read_policy(database: &Path, project: ProjectTrustProjectId) -> ManagedPolicy {
    let authority_id = main_authority(database);
    let path = sidecar_path(database);
    let identity = read_only(&path)
        .query_row(
            "SELECT schema_kind,schema_version,instance_epoch,authority_id
             FROM project_trust_schema WHERE id=1",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .expect("read exact T1 sidecar identity");
    assert_eq!(identity.0, "runne.project-trust");
    assert_eq!(identity.1, 3);
    assert!(identity.2 > 0);
    assert_eq!(identity.3.as_slice(), authority_id.as_slice());
    let connection = read_only(&path);
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM managed_effect_policies", [], |r| {
            r.get(0)
        })
        .expect("count managed policy rows");
    assert_eq!(rows, 1, "fixture sidecar has exactly one policy row");
    let store = runne_store::ProjectTrustStore::open(database, authority_id)
        .expect("open canonical T1 Store view");
    let lease = store
        .acquire_effect_lease(project)
        .expect("current-fence T1 readback");
    let snapshot = lease.snapshot().expect("read canonical policy snapshot");
    assert_eq!(snapshot.record.instance_epoch as i64, identity.2);
    assert_eq!(snapshot.policy.version, 1);
    assert!(snapshot.is_valid());
    let digest = managed_effect_policy_digest_v2(project, &snapshot)
        .expect("canonical managed policy digest");
    ManagedPolicy {
        project_id: *project.as_bytes(),
        authority_id,
        schema_version: identity.1,
        snapshot,
        digest,
    }
}

fn main_authority(database: &Path) -> [u8; 16] {
    let connection = read_only(database);
    runne_store::schema::read_authority_id(&connection)
        .expect("read main runtime authority")
        .expect("main runtime authority is present")
}

fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open read-only fixture view")
}

fn sidecar_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".project-trust");
    PathBuf::from(path)
}

fn id_bytes(id: runne_runtime_client::CanonicalId) -> [u8; 16] {
    uuid::Uuid::parse_str(&id.to_string())
        .expect("canonical fixture id")
        .into_bytes()
}

fn id_from_bytes(bytes: [u8; 16]) -> runne_runtime_client::CanonicalId {
    runne_runtime_client::CanonicalId::parse(&uuid::Uuid::from_bytes(bytes).to_string())
        .expect("stored managed Ask TaskRun id")
}

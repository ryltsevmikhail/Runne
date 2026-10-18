use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ProjectTrustEffectPolicySnapshot,
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
    managed_effect_policy_digest_v2,
};
use rusqlite::{Connection, TransactionBehavior, params};
use std::{path::Path, path::PathBuf, sync::OnceLock};

#[path = "managed_ask/assertions.rs"]
mod assertions;
pub(super) use assertions::{
    assert_human_create_admission, assert_pending_create_no_release, assert_retained_sidecar,
};

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

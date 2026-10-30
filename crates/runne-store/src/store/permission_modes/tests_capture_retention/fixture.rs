use crate::{
    ProjectTrustStore, ProjectWorkspaceStore,
    schema::{self, ConnectionMode},
    store::{
        ProtectedNativeLaunchContext, StoreTransaction,
        taskrun_local_command::{
            PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
        },
    },
};
use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::PermissionScope,
    ports::{EventStoreError, ProjectWorkspaceRepository, RuntimeAuthorityId},
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus},
};
use runne_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use runne_platform::local_command_linux::{LinuxCompositeScopeAdmission, LinuxPermissionOwnerV1};
use std::{
    fs::File,
    sync::{Arc, Mutex, MutexGuard},
};

#[path = "fixture_existing_database.rs"]
mod existing_database;
pub(super) use existing_database::{ControllerDatabase, ExistingDatabase};

pub(super) struct Fixture {
    pub root: tempfile::TempDir,
    pub store: StoreTransaction,
    pub trust: Arc<ProjectTrustStore>,
    pub native: Arc<LinuxCompositeScopeAdmission>,
    pub held: File,
    pub project: ProjectId,
    pub scope: PermissionScope,
    pub principal: ApiPrincipalId,
    pub launch: ProtectedNativeLaunchContext,
}

pub(super) fn command_id() -> CommandId {
    CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes())
}
pub(super) fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).unwrap()
}
pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_root(tempfile::tempdir().unwrap())
    }

    pub fn with_root(root: tempfile::TempDir) -> Self {
        Self::with_root_and_fence(root, |fence| fence)
    }

    // Test-only seam: decorate the same genuine descriptor owner before registration.
    pub fn with_root_and_fence(
        root: tempfile::TempDir,
        decorate: impl FnOnce(Arc<dyn PermissionRootFenceOwnerV1>) -> Arc<dyn PermissionRootFenceOwnerV1>,
    ) -> Self {
        Self::with_root_fence_database(root, decorate, None)
    }

    pub fn with_root_and_existing_database(
        root: tempfile::TempDir,
        database: ExistingDatabase<'_>,
    ) -> Self {
        Self::with_root_fence_database(root, |fence| fence, Some(database))
    }

    fn with_root_fence_database(
        root: tempfile::TempDir,
        decorate: impl FnOnce(Arc<dyn PermissionRootFenceOwnerV1>) -> Arc<dyn PermissionRootFenceOwnerV1>,
        existing: Option<ExistingDatabase<'_>>,
    ) -> Self {
        let daemon = root.path().join("runtime/daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for path in [root.path(), daemon.parent().unwrap(), daemon.as_path()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let workspace = root.path().join("workspace");
        let protected = root.path().join("protected");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&protected).unwrap();
        let held = File::open(&workspace).unwrap();
        let native = Arc::new(
            LinuxCompositeScopeAdmission::new(&[&File::open(protected).unwrap()]).unwrap(),
        );
        let owner = LinuxPermissionOwnerV1::new(native.clone()).unwrap();
        let authority = existing.as_ref().map(|d| d.authority)
            .unwrap_or_else(|| uuid::Uuid::now_v7().into_bytes());
        let runtime = RuntimeAuthorityId(hex::encode(authority));
        let project = ProjectId::from_bytes(uuid::Uuid::now_v7().into_bytes());
        let workspace_id = WorkspaceId::from_bytes(uuid::Uuid::now_v7().into_bytes());
        let trust =
            Arc::new(ProjectTrustStore::open(&daemon.join("trust.sqlite"), authority).unwrap());
        let trust_id = ProjectTrustProjectId::from_bytes(project.into_bytes());
        let initial = trust.load(trust_id).unwrap();
        trust
            .commit(trust_id, ProjectTrustStatus::Trusted, 0, initial.token())
            .unwrap();
        let (db, writer, reader) = match existing {
            Some(database) => database.open().unwrap(),
            None => {
                let db = daemon.join("store.sqlite");
                let writer = schema::open_managed_connection(&db, ConnectionMode::Writer).unwrap();
                schema::apply_migrations(&writer).unwrap();
                schema::ensure_authority_id(&writer, &authority).unwrap();
                schema::ensure_event_log_lineage_id(&writer).unwrap();
                let reader = schema::open_managed_connection(&db, ConnectionMode::Reader).unwrap();
                (db, writer, reader)
            }
        };
        let fence = decorate(held_root_fence(&held, workspace_id, 2));
        let store = StoreTransaction::open_with_connections_and_permission_owner(
            db.to_str().unwrap(),
            writer,
            reader,
            runtime.clone(),
            Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
            trust.clone(),
            owner,
            fence,
        )
        .unwrap();
        let principal = ApiPrincipalId::new("capture-owner").unwrap();
        let repository = ProjectWorkspaceStore::from_store(store.clone());
        repository
            .create_project(
                principal.as_str(),
                command_id(),
                &key("project"),
                Project::create(
                    project,
                    ProjectWorkspaceDisplayName::new("Capture project".into()).unwrap(),
                ),
            )
            .unwrap();
        repository
            .create_workspace(
                principal.as_str(),
                command_id(),
                &key("workspace"),
                Workspace::create(
                    workspace_id,
                    project,
                    ProjectWorkspaceDisplayName::new("Capture workspace".into()).unwrap(),
                ),
            )
            .unwrap();
        repository
            .open_workspace(
                principal.as_str(),
                command_id(),
                &key("open"),
                workspace_id,
                1,
            )
            .unwrap();
        // Test-only launch/session authority: not native authentication or PAM.
        let launch = ProtectedNativeLaunchContext::new([0x61; 16], [0x62; 16], [0x63; 16], 7, 9)
            .unwrap()
            .with_protected_session_id(uuid::Uuid::now_v7().into_bytes())
            .unwrap();
        Self {
            root,
            store,
            trust,
            native,
            held,
            project,
            scope: PermissionScope {
                runtime_authority_id: runtime,
                principal_id: principal.clone(),
                workspace_id,
            },
            principal,
            launch,
        }
    }
    pub fn trust_id(&self) -> ProjectTrustProjectId {
        ProjectTrustProjectId::from_bytes(self.project.into_bytes())
    }
}

pub(super) fn held_root_fence(
    held: &File,
    workspace: WorkspaceId,
    version: u64,
) -> Arc<dyn PermissionRootFenceOwnerV1> {
    Arc::new(TestHeldRootFence {
        file: Mutex::new(held.try_clone().unwrap()),
        workspace,
        version,
        identity: *LinuxCompositeScopeAdmission::workspace_root_identity(held)
            .unwrap()
            .as_bytes(),
    })
}

// Test-only root authority with a real descriptor and serialized lifetime.
// On Linux both native workspace_root_identity and broker unix_support use
// SHA256(st_dev as u64 BE || st_ino as u64 BE); no domain substitution occurs.
struct TestHeldRootFence {
    file: Mutex<File>,
    workspace: WorkspaceId,
    version: u64,
    identity: [u8; 32],
}
struct TestHeldRootGuard<'a> {
    file: MutexGuard<'a, File>,
    version: u64,
    identity: [u8; 32],
}
impl PermissionRootFenceOwnerV1 for TestHeldRootFence {
    fn acquire<'a>(
        &'a self,
        request: &PermissionRootFenceRequestV1,
    ) -> Result<Box<dyn PermissionRootFenceGuardV1 + 'a>, EventStoreError> {
        let file = self.file.lock().map_err(|_| EventStoreError::Unavailable)?;
        let observed = LinuxCompositeScopeAdmission::workspace_root_identity(&file)
            .map_err(|_| EventStoreError::Unavailable)?;
        if request.workspace_id() != self.workspace
            || request.workspace_version() != self.version
            || request.broker_root_version() != self.version
            || request.broker_root_identity() != &self.identity
            || observed.as_bytes() != &self.identity
        {
            return Err(EventStoreError::CorruptData);
        }
        Ok(Box::new(TestHeldRootGuard {
            file,
            version: self.version,
            identity: self.identity,
        }))
    }
}
impl PermissionRootFenceGuardV1 for TestHeldRootGuard<'_> {
    fn workspace(&self) -> &File {
        &self.file
    }
    fn broker_root_version(&self) -> u64 {
        self.version
    }
    fn broker_root_identity(&self) -> &[u8; 32] {
        &self.identity
    }
}

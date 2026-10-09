use std::path::{Path, PathBuf};
use std::sync::Arc;

use runne_api::ApiPrincipalId;
use runne_application::permission_modes::{PermissionMode, PermissionScope, PresetVersion};
use runne_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_application::project_trust::{
    ProjectTrustEffectLease, ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
};
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use rusqlite::OptionalExtension;

use super::hex;
use crate::project_workspace::ProjectWorkspaceStore;
use crate::schema::{self, ConnectionMode};
use crate::store::permission_modes::model::{
    IssuedNativeModeConfirmationV2, NativeModeConfirmationRequestV2,
    PermissionModeAuthorityContext, ProtectedNativeLaunchContext,
};
use crate::{ProjectTrustStore, store::StoreTransaction as RuntimeStore};

const AUTHORITY: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
];
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000041";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000042";
const SESSION: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51,
];

#[derive(Clone, Copy)]
pub(super) enum Storage {
    Memory,
    File,
}

pub(super) struct Fixture {
    pub _root: tempfile::TempDir,
    pub db_path: PathBuf,
    pub store: Option<RuntimeStore>,
    pub trust: ProjectTrustStore,
    pub trust_lease: Option<Box<dyn ProjectTrustEffectLease>>,
    pub project_id: ProjectId,
    pub scope: PermissionScope,
    pub principal: ApiPrincipalId,
    pub launch: ProtectedNativeLaunchContext,
}

impl Fixture {
    pub fn new(storage: Storage) -> Self {
        let root = tempfile::tempdir().unwrap();
        let daemon = root.path().join("runtime/daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(
                daemon.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db_path = match storage {
            Storage::Memory => PathBuf::from(":memory:"),
            Storage::File => daemon.join("permission-modes.sqlite"),
        };
        let runtime = RuntimeAuthorityId(hex(&AUTHORITY));
        let guard = Arc::new(runne_security::SecretBroker::new().prohibited_content_guard());
        let store = match storage {
            Storage::Memory => {
                let writer = memory_connection();
                let reader = memory_connection();
                // Unit fixtures skip startup gates because `:memory:` cannot use WAL.
                RuntimeStore {
                    inner: Arc::new(crate::store::StoreInner {
                        writer: std::sync::Mutex::new(writer),
                        reader: std::sync::Mutex::new(reader),
                        id_counter: std::sync::atomic::AtomicU64::new(0),
                        permission_owner: None,
                    }),
                    runtime_authority_id: runtime,
                    prohibited_content: guard,
                }
            }
            Storage::File => {
                initialize_file(&db_path);
                RuntimeStore::open(db_path.to_str().unwrap(), runtime, guard).unwrap()
            }
        };
        let project_id: ProjectId = PROJECT.parse().unwrap();
        let project_trust_id = ProjectTrustProjectId::from_bytes(project_id.into_bytes());
        let trust =
            ProjectTrustStore::open(&daemon.join("trust-anchor.sqlite"), AUTHORITY).unwrap();
        let initial = trust.load(project_trust_id).unwrap();
        trust
            .commit(
                project_trust_id,
                ProjectTrustStatus::Trusted,
                0,
                initial.token(),
            )
            .unwrap();
        let trust_lease = trust.acquire_effect_lease(project_trust_id).unwrap();
        let principal = ApiPrincipalId::new("permission-mode-owner").unwrap();
        let workspace_id: WorkspaceId = WORKSPACE.parse().unwrap();
        seed_workspace(&store, &principal, project_id, workspace_id);
        let launch = ProtectedNativeLaunchContext::new([0x61; 16], [0x62; 16], [0x63; 16], 7, 9)
            .unwrap()
            .with_protected_session_id(SESSION)
            .unwrap();
        let scope = PermissionScope {
            runtime_authority_id: RuntimeAuthorityId(hex(&AUTHORITY)),
            principal_id: principal.clone(),
            workspace_id,
        };
        Self {
            _root: root,
            db_path,
            store: Some(store),
            trust,
            trust_lease: Some(trust_lease),
            project_id,
            scope,
            principal,
            launch,
        }
    }

    pub fn store(&self) -> &RuntimeStore {
        self.store.as_ref().expect("Store is open")
    }

    pub fn authority(&self) -> PermissionModeAuthorityContext<'_> {
        self.authority_with(Some(&self.launch))
    }

    pub fn authority_with<'a>(
        &'a self,
        launch: Option<&'a ProtectedNativeLaunchContext>,
    ) -> PermissionModeAuthorityContext<'a> {
        PermissionModeAuthorityContext::new(
            &self.principal,
            ProjectTrustProjectId::from_bytes(self.project_id.into_bytes()),
            self.trust_lease.as_deref().expect("T1 lease is held"),
            launch,
        )
    }

    pub fn change_trust_policy(&mut self) {
        drop(self.trust_lease.take());
        let id = ProjectTrustProjectId::from_bytes(self.project_id.into_bytes());
        let current = self.trust.load(id).unwrap();
        self.trust
            .commit(id, ProjectTrustStatus::Managed, 1, current.token())
            .unwrap();
        self.trust_lease = Some(self.trust.acquire_effect_lease(id).unwrap());
    }

    pub fn request(&self, mode: PermissionMode, suffix: &str) -> NativeModeConfirmationRequestV2 {
        NativeModeConfirmationRequestV2 {
            command_id: CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            idempotency_key: IdempotencyKey::new(format!("permission-v2-{suffix}")).unwrap(),
            scope: self.scope.clone(),
            expected_authorization_revision: 0,
            requested_mode: mode,
            preset_version: PresetVersion::V1,
            expires_at_unix_ms: None,
        }
    }

    pub fn bump_workspace_version(&self) {
        self.store()
            .inner
            .writer
            .lock()
            .unwrap()
            .execute(
                "UPDATE workspaces SET version=version+1 WHERE workspace_id=?1",
                [self.scope.workspace_id.as_bytes().as_slice()],
            )
            .unwrap();
    }

    pub fn row_phase(&self, issued: &IssuedNativeModeConfirmationV2) -> (i64, i64) {
        self.store().inner.writer.lock().unwrap().query_row(
            "SELECT state,confirmation_phase FROM permission_mode_native_challenges WHERE challenge_id=?1",
            [issued.challenge_id().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap()
    }

    pub fn selection_revision(&self) -> Option<i64> {
        self.store().inner.writer.lock().unwrap().query_row(
            "SELECT authorization_revision FROM permission_mode_selections WHERE workspace_id=?1",
            [self.scope.workspace_id.as_bytes().as_slice()], |row| row.get(0),
        ).optional().unwrap()
    }

    pub fn receipt_count(&self) -> i64 {
        self.store()
            .inner
            .writer
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM permission_mode_command_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    pub fn abort_receipt_inserts(&self, enabled: bool) {
        let sql = if enabled {
            "CREATE TRIGGER test_abort_mode_receipt BEFORE INSERT ON permission_mode_command_receipts
             BEGIN SELECT RAISE(ABORT,'fixture receipt failure'); END"
        } else {
            "DROP TRIGGER test_abort_mode_receipt"
        };
        self.store()
            .inner
            .writer
            .lock()
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}

fn initialize_file(path: &Path) {
    let connection = schema::open_managed_connection(path, ConnectionMode::Writer).unwrap();
    schema::apply_migrations(&connection).unwrap();
    schema::ensure_authority_id(&connection, &AUTHORITY).unwrap();
    schema::ensure_event_log_lineage_id(&connection).unwrap();
}

fn memory_connection() -> schema::ManagedConnection {
    let connection =
        schema::open_managed_connection(Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    schema::apply_migrations(&connection).unwrap();
    schema::ensure_authority_id(&connection, &AUTHORITY).unwrap();
    schema::ensure_event_log_lineage_id(&connection).unwrap();
    connection
}

fn seed_workspace(
    store: &RuntimeStore,
    principal: &ApiPrincipalId,
    project_id: ProjectId,
    workspace_id: WorkspaceId,
) {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    repository
        .create_project(
            principal.as_str(),
            CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            &IdempotencyKey::new("permission-v2-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("V2 fixture project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            principal.as_str(),
            CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            &IdempotencyKey::new("permission-v2-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("V2 fixture workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .open_workspace(
            principal.as_str(),
            CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
            &IdempotencyKey::new("permission-v2-open").unwrap(),
            workspace_id,
            1,
        )
        .unwrap();
}

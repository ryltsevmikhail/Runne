use std::sync::Arc;

use runne_application::ports::{
    ApplicationCommandContext, ProjectWorkspaceRepository, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::service::TaskRunService;
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use runne_store::{ProjectWorkspaceStore, schema::ManagedConnection};

use crate::validated_reopen::{self, MainDatabaseIdentity, ValidatedTestDatabase};

pub const PROJECT: [u8; 16] = id(0x11);
pub const PROJECT_2: [u8; 16] = id(0x12);
pub const WORKSPACE: [u8; 16] = id(0x21);

const fn id(tail: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x47, 0xa2, 0x4f, 0x8c, 0x7b, 0x52, 0x8c, 0x35, 0x7a, 0x3a, 0x14, 0xc2, 0xd9,
        tail,
    ]
}

pub struct Database {
    pub file: ValidatedTestDatabase,
    pub identity: MainDatabaseIdentity,
    pub store: StoreTransaction,
}

impl Database {
    pub fn new(name: &str) -> Self {
        let file = ValidatedTestDatabase::new(name);
        let (store, identity) =
            validated_reopen::initialize_store(file.path(), authority(), guard()).unwrap();
        Self {
            file,
            identity,
            store,
        }
    }

    pub fn repository(&self) -> ProjectWorkspaceStore {
        ProjectWorkspaceStore::from_store(self.store.clone())
    }

    pub fn reopen(&self) -> ProjectWorkspaceStore {
        let store =
            validated_reopen::reopen_store(self.file.path(), self.identity, authority(), guard())
                .unwrap();
        ProjectWorkspaceStore::from_store(store)
    }

    pub fn task_runs(
        &self,
    ) -> TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction> {
        TaskRunService::new(
            self.store.clone(),
            self.store.clone(),
            self.store.clone(),
            authority(),
        )
    }

    pub fn connection(&self) -> ManagedConnection {
        validated_reopen::open_validated_connection(self.file.path(), self.identity).unwrap()
    }
}

pub fn authority() -> RuntimeAuthorityId {
    RuntimeAuthorityId("project-workspace-test-authority".into())
}

pub fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

pub fn command(tail: u8) -> CommandId {
    CommandId::from_bytes(id(tail))
}

pub fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).unwrap()
}

pub fn project(id: [u8; 16], name: &str) -> Project {
    Project::create(
        ProjectId::from_bytes(id),
        ProjectWorkspaceDisplayName::new(name.into()).unwrap(),
    )
}

pub fn workspace(id: [u8; 16], project: [u8; 16], name: &str) -> Workspace {
    Workspace::create(
        WorkspaceId::from_bytes(id),
        ProjectId::from_bytes(project),
        ProjectWorkspaceDisplayName::new(name.into()).unwrap(),
    )
}

pub fn create_project<R: ProjectWorkspaceRepository>(repository: &R) -> Project {
    repository
        .create_project(
            "owner",
            command(1),
            &key("create-project"),
            project(PROJECT, "One"),
        )
        .unwrap()
}

pub fn create_workspace<R: ProjectWorkspaceRepository>(repository: &R) -> Workspace {
    repository
        .create_workspace(
            "owner",
            command(2),
            &key("create-workspace"),
            workspace(WORKSPACE, PROJECT, "Workspace"),
        )
        .unwrap()
}

pub fn task_context(tail: u8, value: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command(tail),
        idempotency_key: key(value),
        principal_id: runne_application::ports::PrincipalId("owner".into()),
        actor: Actor::new("test-actor").unwrap(),
    }
}

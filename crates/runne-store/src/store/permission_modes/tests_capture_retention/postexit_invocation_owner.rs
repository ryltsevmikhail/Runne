//! Owner-enabled view after ownerless recovery; never replaces original rows.
use super::super::{fixture, target::binding::BindingContext};
use super::{metadata::Area, observations, paths};
use crate::{ProjectTrustStore, schema::ConnectionMode, store::StoreTransaction};
use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::PermissionScope,
    ports::RuntimeAuthorityId,
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId},
};
use runne_domain::{id::ProjectId, task_run::TaskRunLocalCommand};
use runne_platform::local_command_linux::{
    LinuxCompositeScopeAdmission, LinuxPermissionOwnerV1, PreparedPermissionTargetV1,
    SealedExecutableSnapshot,
};
use std::{fs::File, path::Path, sync::Arc};

pub(super) struct OwnerView {
    pub store: StoreTransaction,
    trust: Arc<ProjectTrustStore>,
    native: Arc<LinuxCompositeScopeAdmission>,
    held: File,
    tool: File,
    project: ProjectId,
    scope: PermissionScope,
    principal: ApiPrincipalId,
}
impl OwnerView {
    pub fn reopen(root: &Path, saved: &Area, trust: Arc<ProjectTrustStore>) -> Self {
        let daemon = saved.daemon(root);
        let nested = root.join(&saved.nested);
        let workspace = nested.join("workspace");
        let protected = nested.join("protected");
        paths::directory(&workspace);
        paths::directory(&protected);
        paths::regular(&workspace.join("tool"));
        let held = File::open(&workspace).unwrap();
        let tool = File::open(workspace.join("tool")).unwrap();
        let protected = File::open(protected).unwrap();
        let native = Arc::new(LinuxCompositeScopeAdmission::new(&[&protected]).unwrap());
        let owner = LinuxPermissionOwnerV1::new(native.clone()).unwrap();
        let project: ProjectId = saved.project.parse().unwrap();
        let trust_id = ProjectTrustProjectId::from_bytes(project.into_bytes());
        assert_eq!(trust.load(trust_id).unwrap(), saved.trust_record());
        let scope = PermissionScope {
            runtime_authority_id: RuntimeAuthorityId(hex::encode(saved.authority)),
            principal_id: ApiPrincipalId::new(saved.principal.clone()).unwrap(),
            workspace_id: saved.workspace.parse().unwrap(),
        };
        let fence = fixture::held_root_fence(&held, scope.workspace_id, 2);
        // Validated connections check original authority AND event-log lineage.
        // Store opening may perform readiness writes: compare original logical rows.
        let store = StoreTransaction::open_with_connections_and_permission_owner(
            daemon.join("store.sqlite").to_str().unwrap(),
            observations::reopen(root, saved, ConnectionMode::ValidatedReopen),
            observations::reader(root, saved),
            scope.runtime_authority_id.clone(),
            Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
            trust.clone(),
            owner,
            fence,
        )
        .unwrap();
        Self {
            store,
            trust,
            native,
            held,
            tool,
            project,
            principal: scope.principal_id.clone(),
            scope,
        }
    }
    pub fn context(&self) -> BindingContext<'_> {
        BindingContext {
            store: &self.store,
            trust: &self.trust,
            native: &self.native,
            held: &self.held,
            project: self.project,
            scope: self.scope.clone(),
            principal: self.principal.clone(),
        }
    }
    pub fn prepare(&self, command: TaskRunLocalCommand) -> PreparedPermissionTargetV1 {
        assert_eq!(command.executable().value(), "tool");
        assert!(
            matches!(command.executable(), runne_domain::task_run::TaskRunExecutable::WorkspaceRelative(p) if p == "tool")
        );
        assert_eq!(command.cwd(), ".");
        let snapshot = SealedExecutableSnapshot::from_held_file(&self.tool).unwrap();
        self.store
            .local_permission_preparation()
            .unwrap()
            .prepare_target(command, &self.held, &self.held, snapshot)
            .unwrap()
    }
}

use super::*;

pub(super) struct Fixture {
    pub(super) _directory: tempfile::TempDir,
    pub(super) root: Arc<ProtectedRootControl>,
    pub(super) channel_keys: ProtectedActivationKeys,
    pub(super) sessions: Arc<Mutex<LocalSessionService>>,
    pub(super) owned: runne_api::ProtectedOwnedLaunchV1,
    pub(super) pending: runne_api::PermissionModeNativePendingV2,
}
pub(super) fn fixture() -> Fixture {
    fixture_with_owner_observation(true)
}
pub(super) fn fixture_with_owner_observation(observe: bool) -> Fixture {
    let (owned, keys, sessions) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let principal = ApiPrincipalId::new(owned.stable().principal_id().to_owned()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = daemon.join("control.sqlite");
    let authority = uuid::Uuid::now_v7();
    let authority_id = RuntimeAuthorityId(authority.simple().to_string());
    initialize_identity(&db, authority.as_bytes());
    let store = StoreTransaction::open(
        db.to_str().unwrap(),
        authority_id.clone(),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = ProjectId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let workspace_id = WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    repository
        .create_project(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .open_workspace(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-open").unwrap(),
            workspace_id,
            1,
        )
        .unwrap();
    let trust_path = daemon.join("trust-anchor.sqlite");
    let trust = ProjectTrustStore::open(&trust_path, *authority.as_bytes()).unwrap();
    let trust_project = ProjectTrustProjectId::from_bytes(project_id.into_bytes());
    let initial = trust.load(trust_project).unwrap();
    trust
        .commit(
            trust_project,
            ProjectTrustStatus::Trusted,
            0,
            initial.token(),
        )
        .unwrap();
    let lease = trust.acquire_effect_lease(trust_project).unwrap();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let launch = ProtectedNativeLaunchContext::new(
        *owned.launch_authority_id(),
        *owned.desktop_host_instance_id(),
        *owned.daemon_instance_id(),
        owned.launch_generation(),
        epoch,
    )
    .unwrap()
    .with_protected_session_id(*owned.session_id())
    .unwrap();
    let scope = PermissionScope {
        runtime_authority_id: authority_id,
        principal_id: principal.clone(),
        workspace_id,
    };
    let command_id = CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let request = NativeModeConfirmationRequestV2 {
        command_id,
        idempotency_key: IdempotencyKey::new("wire-mode").unwrap(),
        scope: scope.clone(),
        expected_authorization_revision: 0,
        requested_mode: PermissionMode::RiskBased,
        preset_version: PresetVersion::V1,
        expires_at_unix_ms: None,
    };
    let authority = PermissionModeAuthorityContext::new(
        &principal,
        trust_project,
        lease.as_ref(),
        Some(&launch),
    );
    store
        .begin_permission_mode_confirmation_v2(request, &authority)
        .unwrap();
    let host = PermissionControlHost::new(
        store.clone(),
        repository.clone(),
        Arc::clone(&sessions),
        None,
    );
    let compatible =
        ProtectedOwnedLaunchV1::compatibility_view_of_enrollment_launch_v3(&owned).unwrap();
    if observe {
        host.observe_launch(&compatible, &keys).unwrap();
    }
    let admission = crate::application::root_handle_admission::RootHandleAdmissionAuthority::new(
        &keys,
        repository,
        store.runtime_authority_id().0.clone(),
        Arc::clone(&sessions),
        crate::application::root_handle_admission::TrustGate::closed(),
    );
    let root = ProtectedRootControl::new_with_permission_control(admission, host);
    let pending = store
        .discover_permission_mode_native_pending_command_v2(&principal, &launch, command_id)
        .unwrap()
        .unwrap();
    Fixture {
        _directory: directory,
        root,
        channel_keys: keys,
        sessions,
        owned: compatible,
        pending,
    }
}

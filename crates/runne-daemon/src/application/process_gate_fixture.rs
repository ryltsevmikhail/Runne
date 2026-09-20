//! Test-support regression pin for the helper-process delivery gate (R-2):
//! the process channel is activation-gated, so `with_process_root` denies
//! BEFORE any native provider access — for untrusted and trusted projects
//! alike, and fail-closed when the authority is absent. Not part of the
//! production surface.

use std::sync::{Arc, Mutex};

use runne_application::ports::RuntimeAuthorityId;
use runne_application::project_trust::{
    ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus, TrustToken,
};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{ProjectTrustStore, ProjectWorkspaceStore, store::StoreTransaction};

use crate::application::root_handle_admission::RootHandleAdmissionAuthority;
use runne_application::local_session::LocalSessionService;
use runne_application::ports::ProjectWorkspaceRepository;

/// Drives the pin; panics with a precise message on any violation.
pub fn process_channel_denies_before_native_access(directory: &std::path::Path) {
    let daemon_dir = directory.join("runne-daemon");
    std::fs::create_dir_all(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let db_path = daemon_dir.join("process-gate.sqlite");
    let store = StoreTransaction::open(
        db_path.to_str().unwrap(),
        RuntimeAuthorityId("process-gate".into()),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .expect("store opens");
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let project_id: runne_domain::id::ProjectId =
        "018f2e3a-7000-7000-8000-0000000000d3".parse().unwrap();
    projects
        .create_project(
            "local-owner",
            runne_domain::id::CommandId::from_bytes([1; 16]),
            &runne_domain::id::IdempotencyKey::new("pg-project").unwrap(),
            runne_domain::project_workspace::Project::create(
                project_id,
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("p".into())
                    .unwrap(),
            ),
        )
        .unwrap();
    projects
        .create_workspace(
            "local-owner",
            runne_domain::id::CommandId::from_bytes([2; 16]),
            &runne_domain::id::IdempotencyKey::new("pg-workspace").unwrap(),
            runne_domain::project_workspace::Workspace::create(
                "018f2e3a-7000-7000-8000-0000000000d2".parse().unwrap(),
                project_id,
                runne_domain::project_workspace::ProjectWorkspaceDisplayName::new("w".into())
                    .unwrap(),
            ),
        )
        .unwrap();

    let sidecar = Arc::new(ProjectTrustStore::open(&db_path, [0x0d; 16]).unwrap());
    let persistence: Arc<dyn ProjectTrustPersistence> = sidecar.clone();
    let trust = crate::application::root_handle_admission::TrustGate::open(Arc::new(
        ProjectTrustPolicyAuthority::new(persistence),
    ));
    let keys = runne_api::LaunchSecret::from_bytes([9; 32])
        .unwrap()
        .derive_keys();
    let sessions = Arc::new(Mutex::new(LocalSessionService::new(
        runne_api::RuntimeSessionBinding::new(
            runne_api::StableRuntimeBinding::new(
                [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
                runne_api::ApiPrincipalId::new("local-owner").unwrap(),
                runne_domain::id::EventLogLineageId::from_bytes([
                    0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2,
                ]),
                "fixture",
                [3; 32],
                [4; 32],
            )
            .unwrap(),
            runne_domain::id::DaemonInstanceId::from_bytes([
                0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4,
            ]),
            1,
            [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 5],
            0,
            runne_domain::event::Sensitivity::Public,
            [6; 32],
        )
        .unwrap(),
        [7; 32],
    )));
    let authority =
        RootHandleAdmissionAuthority::new(&keys, projects, "process-gate".into(), sessions, trust);
    let gateway = crate::application::root_handle_admission::gateway_for_tests(authority);
    let workspace_id: runne_domain::id::WorkspaceId =
        "018f2e3a-7000-7000-8000-0000000000d2".parse().unwrap();

    // Untrusted project: rejected; the native callback never runs.
    let reached = std::cell::Cell::new(false);
    let outcome = gateway.with_process_root(workspace_id, |_root| {
        reached.set(true);
        Ok(())
    });
    assert!(
        matches!(outcome, Err(RootHandleBrokerError::Rejected)),
        "untrusted project must reject the process channel"
    );
    assert!(!reached.get(), "native provider must not be reached");

    // Trusted project: still rejected — the channel is activation-gated.
    let epoch = sidecar.instance_epoch().unwrap();
    sidecar
        .commit(
            ProjectTrustProjectId::from_bytes(*project_id.as_bytes()),
            ProjectTrustStatus::Trusted,
            0,
            TrustToken::new(epoch, 0),
        )
        .unwrap();
    let reached = std::cell::Cell::new(false);
    let outcome = gateway.with_process_root(workspace_id, |_root| {
        reached.set(true);
        Ok(())
    });
    assert!(
        matches!(outcome, Err(RootHandleBrokerError::Rejected)),
        "trusted project stays channel-denied (activation gate)"
    );
    assert!(!reached.get(), "trusted denial also precedes native access");

    // Absent authority: fail closed as Unavailable.
    use crate::application::root_handle_admission::closed_gateway_for_tests;
    use runne_platform_desktop::RootHandleBrokerError;
    let closed = closed_gateway_for_tests();
    assert!(matches!(
        closed.with_process_root(workspace_id, |_| Ok(())),
        Err(RootHandleBrokerError::Unavailable)
    ));
}

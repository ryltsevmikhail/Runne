//! Real protected-daemon regression for the CLI owner's session renewal.
//!
//! The daemon fences every admitted root handle when the protected session is
//! rotated. The installed failure was a client that renewed the session and
//! kept serving: workspace diffs (F4) reported `runtime is unavailable`, and an
//! already accepted coding run failed its tool plan before any provider
//! delivery and stayed `running` without a worker.
use super::*;
use crate::protected_runtime_tests::fixture::{Fixture, fixture, seed_workspace};
use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor,
};
use runne_runtime_client::RuntimeApiErrorKind;

fn start_owner(fixture: &Fixture, workspace: CanonicalId) -> BackendOwner {
    let project = fixture.temporary.join("project-root");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(&fixture.daemon, &fixture.root)
        .expect("protected launch spec for the renewal fixture");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().expect("start protected runtime");
    let runtime = tokio::runtime::Runtime::new().expect("owner renewal runtime");
    let client = runtime.block_on(async {
        let profile = supervisor
            .take_runtime_profile()
            .expect("one-time runtime profile");
        let client = profile
            .connect(TIMEOUT)
            .await
            .expect("authenticated client");
        supervisor
            .record_client_ready(&client)
            .expect("client readiness proof");
        client
    });
    BackendOwner {
        client,
        workspace_id: Some(workspace),
        project_label: project.display().to_string(),
        selected_profile: None,
        supervisor: Some(supervisor),
        project,
        runtime_root: fixture.root.clone(),
        renewed_at: Instant::now(),
        pending_registration: None,
        registration_intent_saved: false,
    }
}

fn diff_availability(
    owner: &BackendOwner,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), RuntimeApiErrorKind> {
    let workspace = owner.workspace_id.expect("bound workspace");
    runtime.block_on(async {
        owner
            .client
            .list_workspace_changes(workspace, 20)
            .await
            .map(|_| ())
            .map_err(|error| error.kind())
    })
}

fn rotate_session(owner: &mut BackendOwner, runtime: &tokio::runtime::Runtime) {
    let profile = owner
        .supervisor
        .as_mut()
        .expect("owned supervisor")
        .renew_profile()
        .expect("protected session renewal");
    let renewed = runtime
        .block_on(profile.connect(TIMEOUT))
        .expect("renewed authenticated client");
    owner
        .supervisor
        .as_mut()
        .expect("owned supervisor")
        .record_client_ready(&renewed)
        .expect("renewed readiness proof");
    owner.client = renewed;
}

#[test]
fn session_rotation_fences_the_root_and_the_owner_rebinds_it() {
    let fixture = fixture();
    let (workspace, _revision, _authority) = seed_workspace(&fixture);
    let mut owner = start_owner(&fixture, workspace);
    let runtime = tokio::runtime::Runtime::new().expect("owner renewal runtime");
    runtime
        .block_on(owner.rebind_workspace_root())
        .expect("initial trusted root admission");
    assert!(
        diff_availability(&owner, &runtime).is_ok(),
        "an admitted root serves the workspace diff API"
    );
    rotate_session(&mut owner, &runtime);
    assert_eq!(
        diff_availability(&owner, &runtime),
        Err(RuntimeApiErrorKind::Unavailable),
        "a rotated session fences the admitted root, so root-gated calls fail closed"
    );
    runtime
        .block_on(owner.rebind_workspace_root())
        .expect("root re-admission after the session rotation");
    assert!(
        diff_availability(&owner, &runtime).is_ok(),
        "the re-bound root restores root-gated runtime calls after renewal"
    );
}

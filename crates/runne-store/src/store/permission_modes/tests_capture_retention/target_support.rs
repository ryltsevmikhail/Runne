//! Small test-only preparation and capture helpers; no alternate admission route.
use super::super::fixture::{Fixture, command_id, key};
use crate::store::{LocalCommandAttemptState, LocalCommandPermissionCaptureV1};
use runne_application::{permission_modes::LocalCommandPermissionBindingV1, ports::*};
use runne_domain::{
    event::Actor,
    task_run::{TaskRunExecutable, TaskRunLocalCommand},
};
use runne_platform::local_command_linux::{PreparedPermissionTargetV1, SealedExecutableSnapshot};

pub(super) fn context(f: &Fixture, label: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id(),
        idempotency_key: key(label),
        principal_id: PrincipalId(f.principal.as_str().into()),
        actor: Actor::new("capture-test").unwrap(),
    }
}

pub(super) fn prepare(
    f: &Fixture,
    command: &TaskRunLocalCommand,
    executable: &[u8],
) -> PreparedPermissionTargetV1 {
    assert!(matches!(command.executable(), TaskRunExecutable::WorkspaceRelative(p) if p == "tool"));
    let workspace = f.root.path().join("workspace");
    let path = workspace.join("tool");
    // Default callers retain the never-executed shebang; native callers supply ELF.
    std::fs::write(&path, executable).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot =
        SealedExecutableSnapshot::from_held_file(&std::fs::File::open(path).unwrap()).unwrap();
    // Domain constructor already validates a bounded relative cwd. The caller owns it.
    let owned_cwd =
        (command.cwd() != ".").then(|| std::fs::File::open(workspace.join(command.cwd())).unwrap());
    let cwd = owned_cwd.as_ref().unwrap_or(&f.held);
    f.store
        .local_permission_preparation()
        .unwrap()
        .prepare_target(command.clone(), &f.held, cwd, snapshot)
        .unwrap()
}

pub(super) fn capture(
    f: &Fixture,
) -> (
    LocalCommandPermissionBindingV1,
    LocalCommandPermissionCaptureV1,
    PreparedPermissionTargetV1,
) {
    let (binding, prepared) = super::prepare(f);
    let observation = prepared.observation();
    let taskrun_id = binding.assignment().taskrun_id;
    let capture = f
        .store
        .capture_local_command_permission(&binding, observation)
        .unwrap();
    assert_eq!(
        capture.canonical_binding_digest,
        *binding.digest().as_bytes()
    );
    assert_eq!(capture.native_owner_id, *observation.owner_id());
    assert_eq!(
        capture.native_owner_generation,
        observation.owner_generation()
    );
    assert_eq!(capture.state, LocalCommandAttemptState::ApprovalPending);
    let route: (i64, i64, i64) = f.store.inner.reader.lock().unwrap().query_row(
        "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(route, (2, 3, 68));
    (binding, capture, prepared)
}

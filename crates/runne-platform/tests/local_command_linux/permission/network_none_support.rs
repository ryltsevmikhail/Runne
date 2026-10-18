use crate::*;
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemScope, ManagedPolicyCoverage,
    NativeScopeAdmissionReceipt, NetworkScope, PermissionScope, admit_invocation_scope,
};
use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ManagedEffectPolicyV1,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus,
};
use runne_domain::id::WorkspaceId;
use runne_platform::local_command_linux::{
    LinuxCommandContainmentV1, LinuxCommandExecutable, LinuxCommandOutputLimitsV1,
    LinuxCompositeScopeAdmission, SealedExecutableSnapshot,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

pub(crate) struct Fixture {
    _root: LinuxManagedAreaRoot,
    pub(crate) area: AreaGuard,
    pub(crate) workspace: Workspace,
    pub(crate) workspace_fd: File,
    pub(crate) cwd: File,
    _protected_dir: tempfile::TempDir,
    _protected_file: File,
    pub(crate) admission: LinuxCompositeScopeAdmission,
    pub(crate) scope: CompositeEffectScope,
    pub(crate) receipt: NativeScopeAdmissionReceipt,
}

pub(crate) fn fixture() -> Option<Fixture> {
    let (_root, area, _identity) = run_or_skip()?;
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let protected_dir = tempfile::tempdir().expect("protected policy root");
    let protected_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(protected_dir.path())
        .expect("held protected root");
    let admission =
        LinuxCompositeScopeAdmission::new(&[&protected_file]).expect("native admission registry");
    let network = NetworkScope::None;
    let scope = closed_scope(
        &admission,
        network,
        EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
    );
    let receipt = admit_invocation_scope(&scope, &admission).expect("closed native scope");
    Some(Fixture {
        _root,
        area,
        workspace,
        workspace_fd,
        cwd,
        _protected_dir: protected_dir,
        _protected_file: protected_file,
        admission,
        scope,
        receipt,
    })
}

pub(crate) fn closed_scope(
    admission: &LinuxCompositeScopeAdmission,
    network: NetworkScope,
    budget: EffectBudget,
) -> CompositeEffectScope {
    let mut rules = [ManagedEffectDecision::Allow; 6];
    if network == NetworkScope::None {
        rules[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    }
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 71,
            revision: 3,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::new(1, rules),
    };
    CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                "closed-network-none-test".to_owned(),
            ),
            principal_id: runne_api::ApiPrincipalId::new("user:network-none-test").unwrap(),
            workspace_id: WorkspaceId::from_bytes([7; 16]),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: BTreeSet::from([
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]),
        },
        network,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
            ProjectTrustProjectId::from_bytes([61; 16]),
            &snapshot,
        )
        .expect("closed snapshot evidence"),
        children: ChildDelegationScope::Unbounded,
        budget,
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: admission
            .protected_control_plane_policy_digest_v2(network)
            .expect("network-none V2 protected identity"),
    }
}

pub(crate) fn python() -> (File, SealedExecutableSnapshot) {
    let file = File::open("/usr/bin/python3").expect("Python executable");
    let sealed = SealedExecutableSnapshot::from_held_file(&file).expect("sealed Python");
    (file, sealed)
}

pub(crate) fn containment(fixture: &Fixture) -> LinuxCommandContainmentV1<'_> {
    LinuxCommandContainmentV1::SameUserCompositeV1 {
        scope: &fixture.scope,
        receipt: fixture.receipt,
        admission: &fixture.admission,
    }
}

pub(crate) fn command<'a>(
    executable: &'a SealedExecutableSnapshot,
    fixture: &'a Fixture,
    argv: Vec<OsString>,
) -> LinuxCommandSpec<'a> {
    LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(executable),
        workspace: &fixture.workspace_fd,
        cwd: &fixture.cwd,
        argv,
        env: Vec::new(),
    }
}

pub(crate) fn limits() -> LinuxCommandOutputLimitsV1 {
    LinuxCommandOutputLimitsV1::new(4096, 4096).unwrap()
}

pub(crate) fn make_inheritable(fd: i32) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
}

pub(crate) fn fd_of<T: AsRawFd>(value: &T) -> i32 {
    value.as_raw_fd()
}

use super::*;
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope,
    ManagedPolicyCoverage, NetworkScope, PermissionScope, admit_invocation_scope,
};
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::{
    LinuxCommandContainmentV1, LinuxCommandExecutable, LinuxCommandOutputLimitsV1,
    LinuxCompositeScopeAdmission, SealedExecutableSnapshot,
};
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt;

#[test]
fn typed_network_none_denies_socket_after_go() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let protected = tempfile::tempdir().expect("protected control-plane root");
    std::fs::write(
        protected.path().join("protected-secret"),
        b"control-plane canary",
    )
    .expect("seed protected canary");
    let protected_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(protected.path())
        .expect("held protected root");
    let admission =
        LinuxCompositeScopeAdmission::new(&[&protected_file]).expect("native admission registry");
    let root_identity = LinuxCompositeScopeAdmission::workspace_root_identity(&workspace_fd)
        .expect("workspace identity");
    let mut permissions = BTreeSet::new();
    permissions.insert(FilesystemPermission::Read);
    let root = FilesystemRoot::new(root_identity, Vec::new()).unwrap();
    let scope = CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                "permission-test-runtime".to_owned(),
            ),
            principal_id: runne_api::ApiPrincipalId::new("user:permission-test").unwrap(),
            workspace_id: runne_domain::id::WorkspaceId::from_bytes([7; 16]),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BoundedRoots(BTreeSet::from([root])),
            permissions,
        },
        network: NetworkScope::None,
        managed_policy: ManagedPolicyCoverage::Unrestricted {
            policy_digest: IntegrityDigest::from_bytes([9; 32]),
        },
        children: ChildDelegationScope::None,
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: Some(4096),
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::WorkspaceBoundV1,
        protected_control_plane_policy_digest: admission.protected_control_plane_policy_digest(),
    };
    let receipt = admit_invocation_scope(&scope, &admission).expect("exact native scope");
    let executable = File::open("/usr/bin/python3").expect("Python executable");
    let command = LinuxCommandSpec {
        executable: LinuxCommandExecutable::HeldFile(&executable),
        workspace: &workspace_fd,
        cwd: &cwd,
        argv: vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from("import socket; socket.socket().connect(('127.0.0.1', 1))"),
        ],
        env: Vec::new(),
    };
    let limits = LinuxCommandOutputLimitsV1::new(4096, 4096).unwrap();
    let containment = LinuxCommandContainmentV1::WorkspaceBoundV1 {
        scope: &scope,
        receipt,
        admission: &admission,
    };
    let mut child = command
        .spawn_gated_with_containment_with_io(&area, b"", limits, containment)
        .expect("stopped typed child");
    assert!(!child.was_released());
    child.release().expect("release typed child");
    let code = child
        .wait(Duration::from_secs(3))
        .expect("network denial exit");
    assert_ne!(
        code, 0,
        "NetworkScope::None must deny a real socket syscall"
    );
    let proof = area.prove_empty().expect("managed area empty after denial");
    proof.revalidate().expect("area remained empty");
    area.remove();
}

#[test]
fn typed_full_access_allows_real_outside_write_and_loopback_socket() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let outside = workspace.0.parent().unwrap().join(format!(
        "runne-broad-outside-{}-{}",
        std::process::id(),
        nonce()[0]
    ));
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener");
    let port = listener.local_addr().unwrap().port().to_string();
    let (network_tx, network_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut bytes = [0_u8; 32];
        let Ok(count) = std::io::Read::read(&mut stream, &mut bytes) else {
            return;
        };
        let _ = network_tx.send(bytes[..count].to_vec());
    });
    let protected = tempfile::tempdir().expect("protected control-plane root");
    let protected_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(protected.path())
        .expect("held protected root");
    let admission =
        LinuxCompositeScopeAdmission::new(&[&protected_file]).expect("native admission registry");
    let mut permissions = BTreeSet::new();
    permissions.insert(FilesystemPermission::Read);
    permissions.insert(FilesystemPermission::Create);
    permissions.insert(FilesystemPermission::Write);
    permissions.insert(FilesystemPermission::Delete);
    let scope = CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                "permission-test-runtime".to_owned(),
            ),
            principal_id: runne_api::ApiPrincipalId::new("user:permission-test").unwrap(),
            workspace_id: runne_domain::id::WorkspaceId::from_bytes([8; 16]),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions,
        },
        network: NetworkScope::BroadSameUser,
        managed_policy: ManagedPolicyCoverage::Unrestricted {
            policy_digest: IntegrityDigest::from_bytes([10; 32]),
        },
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: Some(1),
            max_bytes: None,
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::SameUserCompositeV1,
        protected_control_plane_policy_digest: admission.protected_control_plane_policy_digest(),
    };
    let receipt = admit_invocation_scope(&scope, &admission).expect("broad native scope");
    let executable = File::open("/usr/bin/bash").expect("Bash executable");
    let sealed = SealedExecutableSnapshot::from_held_file(&executable).expect("sealed Bash");
    let script = format!(
        "if cat {}/protected-secret >/dev/null; then exit 42; fi; printf broad-write > {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf network-ok >&3",
        protected.path().display(),
        outside.display(),
        port
    );
    let command = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&sealed),
        workspace: &workspace_fd,
        cwd: &cwd,
        argv: vec![
            OsString::from("/usr/bin/bash"),
            OsString::from("-c"),
            OsString::from(script),
        ],
        env: Vec::new(),
    };
    let limits = LinuxCommandOutputLimitsV1::new(4096, 4096).unwrap();
    let containment = LinuxCommandContainmentV1::SameUserCompositeV1 {
        scope: &scope,
        receipt,
        admission: &admission,
    };
    let mut child = command
        .spawn_gated_with_containment_with_io(&area, b"", limits, containment)
        .expect("stopped broad child");
    child.release().expect("release broad child");
    let code = child
        .wait(Duration::from_secs(5))
        .expect("broad child exit");
    assert_eq!(
        code, 0,
        "full_access broad process must complete real effects"
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside same-user write"),
        b"broad-write"
    );
    assert_eq!(
        network_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        b"network-ok".to_vec()
    );
    let proof = area
        .prove_empty()
        .expect("managed area empty after broad child");
    proof.revalidate().expect("broad area remained empty");
    area.remove();
    let _ = std::fs::remove_file(outside);
}

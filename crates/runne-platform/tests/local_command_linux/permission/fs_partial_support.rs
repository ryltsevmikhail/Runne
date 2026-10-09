use crate::{AreaGuard, LinuxCommandSpec, LinuxManagedAreaRoot, Workspace, run_or_skip};
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, FilesystemScope, ManagedPolicyCoverage, NetworkScope,
    PermissionScope, admit_invocation_scope,
};
use runne_application::project_trust::{
    ManagedEffectClass, ManagedEffectDecision, ManagedEffectPolicyV1,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus,
};
use runne_domain::id::WorkspaceId;
use runne_platform::local_command_linux::{
    LinuxCommandContainmentV2, LinuxCommandExecutable, LinuxCommandOutputLimitsV1,
    LinuxCompositeScopeAdmission, SealedExecutableSnapshot,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::{Duration, Instant};

pub(crate) struct Fixture {
    _root: LinuxManagedAreaRoot,
    pub(crate) area: AreaGuard,
    pub(crate) workspace: Workspace,
    pub(crate) workspace_fd: File,
    pub(crate) cwd: File,
    pub(crate) protected_dir: tempfile::TempDir,
    pub(crate) admission: LinuxCompositeScopeAdmission,
    pub(crate) scope: CompositeEffectScope,
}

pub(crate) fn fixture(
    network: NetworkScope,
    rights: impl IntoIterator<Item = FilesystemPermission>,
    denied: Option<ManagedEffectClass>,
) -> Option<Fixture> {
    let (_root, area, _) = run_or_skip()?;
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let protected_dir = tempfile::tempdir().expect("protected control-plane root");
    std::fs::write(protected_dir.path().join("protected-secret"), b"hidden")
        .expect("seed protected root");
    let protected = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(protected_dir.path())
        .expect("hold protected root");
    let admission = LinuxCompositeScopeAdmission::new(&[&protected]).expect("admission registry");
    let mut decisions = [ManagedEffectDecision::Allow; 6];
    if network == NetworkScope::None {
        decisions[ManagedEffectClass::NetworkUse.tag() as usize - 1] = ManagedEffectDecision::Deny;
    }
    if let Some(class) = denied {
        decisions[class.tag() as usize - 1] = ManagedEffectDecision::Deny;
    }
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: ProjectTrustRecord {
            status: ProjectTrustStatus::Managed,
            instance_epoch: 31,
            revision: 4,
            managed_deny_mask: 0,
        },
        policy: ManagedEffectPolicyV1::new(1, decisions),
    };
    let scope = CompositeEffectScope {
        permission_scope: PermissionScope {
            runtime_authority_id: runne_application::ports::RuntimeAuthorityId(
                "partial-fs-native-test".to_owned(),
            ),
            principal_id: runne_api::ApiPrincipalId::new("user:partial-fs-test").unwrap(),
            workspace_id: WorkspaceId::from_bytes([27; 16]),
        },
        filesystem: FilesystemScope {
            posture: FilesystemPosture::BroadSameUser,
            permissions: rights.into_iter().collect::<BTreeSet<_>>(),
        },
        network,
        managed_policy: ManagedPolicyCoverage::from_closed_snapshot(
            ProjectTrustProjectId::from_bytes([29; 16]),
            &snapshot,
        )
        .expect("closed managed snapshot"),
        children: ChildDelegationScope::Unbounded,
        budget: EffectBudget {
            max_operations: None,
            max_bytes: None,
        },
        lifetime_ms: 30_000,
        containment: ContainmentStrategy::SameUserCompositeV2,
        protected_control_plane_policy_digest: admission
            .protected_control_plane_policy_digest_v3(network)
            .expect("V3 network identity"),
    };
    Some(Fixture {
        _root,
        area,
        workspace,
        workspace_fd,
        cwd,
        protected_dir,
        admission,
        scope,
    })
}

impl Fixture {
    pub(crate) fn cleanup(self) {
        self.area.remove();
    }
}

pub(crate) fn run_python(fixture: &Fixture, code: &str, args: &[&str]) -> i32 {
    let receipt = admit_invocation_scope(&fixture.scope, &fixture.admission)
        .expect("exact V2 native receipt");
    let exe = File::open("/usr/bin/python3").expect("Python executable");
    let sealed = SealedExecutableSnapshot::from_held_file(&exe).expect("sealed Python");
    let command = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&sealed),
        workspace: &fixture.workspace_fd,
        cwd: &fixture.cwd,
        argv: std::iter::once(std::ffi::OsString::from("/usr/bin/python3"))
            .chain([
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from(code),
            ])
            .chain(args.iter().map(std::ffi::OsString::from))
            .collect(),
        env: Vec::new(),
    };
    let containment = LinuxCommandContainmentV2::SameUserCompositeV2 {
        scope: &fixture.scope,
        receipt,
        admission: &fixture.admission,
    };
    command
        .preflight_with_containment_v2(containment)
        .expect("V2 preflight");
    let limits = LinuxCommandOutputLimitsV1::new(4096, 4096).unwrap();
    let mut child = command
        .spawn_gated_with_containment_v2_with_io(&fixture.area, b"", limits, containment)
        .expect("stopped V2 child");
    assert!(!child.was_released());
    child.release().expect("GO");
    let deadline = Instant::now() + Duration::from_secs(5);
    let code = loop {
        child.poll_output().expect("poll bounded output");
        if let Some(code) = child.try_wait().expect("poll child exit") {
            break code;
        }
        assert!(Instant::now() < deadline, "V2 child timed out");
        std::thread::sleep(Duration::from_millis(5));
    };
    let output = child.take_output();
    if code != 0 && (!output.stdout.is_empty() || !output.stderr.is_empty()) {
        eprintln!(
            "V2 child stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        eprintln!(
            "V2 child stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let proof = fixture.area.prove_empty().expect("managed area empty");
    proof.revalidate().expect("managed area remains empty");
    code
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn static_exit_snapshot() -> (tempfile::TempDir, SealedExecutableSnapshot) {
    let dir = tempfile::tempdir().expect("static executable fixture directory");
    let path = dir.path().join("static-exit");
    let mut elf = vec![0u8; 129];
    elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    elf[88..96].copy_from_slice(&0x400000u64.to_le_bytes());
    elf[96..104].copy_from_slice(&129u64.to_le_bytes());
    elf[104..112].copy_from_slice(&129u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[120..].copy_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
    std::fs::write(&path, elf).expect("write static fixture");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("make static executable");
    let file = File::open(path).expect("open static executable");
    (
        dir,
        SealedExecutableSnapshot::from_held_file(&file).expect("seal static executable"),
    )
}

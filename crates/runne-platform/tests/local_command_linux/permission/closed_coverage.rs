use super::network_none::support as none;
use runne_application::permission_modes::{
    ChildDelegationScope, ContainmentStrategy, EffectBudget, EffectiveModeState,
    FilesystemPermission, FilesystemPosture, FilesystemRoot, FilesystemScope, IntegrityDigest,
    ManagedPolicyCoverage, NativeAdmissionError, NetworkScope, PermissionMode, PresetVersion,
    admit_effective_mode, admit_invocation_scope,
};
use runne_domain::id::WorkspaceId;
use runne_platform::local_command_linux::{LinuxCommandContainmentV1, LinuxCommandError};
use std::collections::BTreeSet;
use std::ffi::OsString;

#[test]
fn closed_network_none_readiness_checks_all_modes_after_real_namespace_preflight() {
    eprintln!("RUN: closed_network_none_readiness_checks_all_modes_after_real_namespace_preflight");
    let Some(fixture) = none::fixture() else {
        return;
    };
    for mode in [
        PermissionMode::AskAlways,
        PermissionMode::RiskBased,
        PermissionMode::FullAccess,
    ] {
        let effective =
            admit_effective_mode(mode, PresetVersion::V1, &fixture.scope, &fixture.admission)
                .expect("closed scope readiness must probe native namespaces for every mode");
        let ready = match effective {
            EffectiveModeState::Ready(ready) => ready,
            EffectiveModeState::NotReady(reason) => {
                panic!("native readiness not ready: {reason:?}")
            }
        };
        assert_eq!(ready.mode(), mode);
        assert!(
            !ready
                .mode_readiness()
                .platform_handle_id()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        );
    }
    fixture.area.remove();
}

#[test]
fn closed_network_none_uses_distinct_v2_identity_and_rejects_legacy_v1_identity() {
    eprintln!("RUN: closed_network_none_uses_distinct_v2_identity_and_rejects_legacy_v1_identity");
    let Some(fixture) = none::fixture() else {
        return;
    };
    let legacy = fixture.admission.protected_control_plane_policy_digest();
    let closed_none = fixture
        .admission
        .protected_control_plane_policy_digest_v2(NetworkScope::None)
        .unwrap();
    let closed_broad = fixture
        .admission
        .protected_control_plane_policy_digest_v2(NetworkScope::BroadSameUser)
        .unwrap();
    assert_ne!(legacy, closed_none);
    assert_ne!(closed_none, closed_broad);
    let mut mislabeled = fixture.scope.clone();
    mislabeled.protected_control_plane_policy_digest = legacy;
    assert_eq!(
        admit_invocation_scope(&mislabeled, &fixture.admission),
        Err(NativeAdmissionError::CompositePolicyUnenforceable)
    );
    fixture.area.remove();
}

#[test]
fn legacy_and_closed_receipts_cannot_replay_across_coverage_versions() {
    eprintln!("RUN: legacy_and_closed_receipts_cannot_replay_across_coverage_versions");
    let Some(fixture) = none::fixture() else {
        return;
    };
    let mut legacy_scope = fixture.scope.clone();
    legacy_scope.network = NetworkScope::BroadSameUser;
    legacy_scope.managed_policy = ManagedPolicyCoverage::Unrestricted {
        policy_digest: IntegrityDigest::from_bytes([19; 32]),
    };
    legacy_scope.budget.max_operations = Some(1);
    legacy_scope.protected_control_plane_policy_digest =
        fixture.admission.protected_control_plane_policy_digest();
    let legacy_receipt = admit_invocation_scope(&legacy_scope, &fixture.admission)
        .expect("legacy scope keeps its V1 admission identity");
    let (_file, sealed) = none::python();
    let command = none::command(
        &sealed,
        &fixture,
        vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from("pass"),
        ],
    );
    let closed = LinuxCommandContainmentV1::SameUserCompositeV1 {
        scope: &fixture.scope,
        receipt: legacy_receipt,
        admission: &fixture.admission,
    };
    assert_eq!(
        command.preflight_with_containment(closed),
        Err(LinuxCommandError::Unverified)
    );
    let legacy = LinuxCommandContainmentV1::SameUserCompositeV1 {
        scope: &legacy_scope,
        receipt: fixture.receipt,
        admission: &fixture.admission,
    };
    assert_eq!(
        command.preflight_with_containment(legacy),
        Err(LinuxCommandError::Unverified)
    );
    fixture.area.remove();
}

#[test]
fn closed_workspace_fsread_cannot_launch_generic_linux_command_spec() {
    eprintln!("RUN: closed_workspace_fsread_cannot_launch_generic_linux_command_spec");
    let Some(fixture) = none::fixture() else {
        return;
    };
    let root_identity =
        runne_platform::local_command_linux::LinuxCompositeScopeAdmission::workspace_root_identity(
            &fixture.workspace_fd,
        )
        .unwrap();
    let mut scope = fixture.scope.clone();
    scope.filesystem = FilesystemScope {
        posture: FilesystemPosture::BoundedRoots(BTreeSet::from([FilesystemRoot::new(
            root_identity,
            Vec::new(),
        )
        .unwrap()])),
        permissions: BTreeSet::from([FilesystemPermission::Read]),
    };
    scope.children = ChildDelegationScope::None;
    scope.budget = EffectBudget {
        max_operations: Some(1),
        max_bytes: Some(4096),
    };
    scope.containment = ContainmentStrategy::WorkspaceBoundV1;
    scope.protected_control_plane_policy_digest = fixture
        .admission
        .protected_control_plane_policy_digest_v2(NetworkScope::None)
        .unwrap();
    let (_file, sealed) = none::python();
    let target = fixture.workspace.0.join("generic-workspace-spawn");
    let command = none::command(
        &sealed,
        &fixture,
        vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from("import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('escaped')"),
            target.clone().into_os_string(),
        ],
    );
    let containment = LinuxCommandContainmentV1::WorkspaceBoundV1 {
        scope: &scope,
        receipt: fixture.receipt,
        admission: &fixture.admission,
    };
    assert_eq!(
        command.preflight_with_containment(containment),
        Err(LinuxCommandError::CompositePolicyUnenforceable)
    );
    assert!(matches!(
        command.spawn_gated_with_containment(&fixture.area, containment),
        Err(LinuxCommandError::CompositePolicyUnenforceable)
    ));
    assert!(!target.exists());
    fixture.area.remove();
}

fn _scope_id_type_anchor(_: WorkspaceId) {}

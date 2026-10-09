use super::network_none::support as none;
use runne_application::permission_modes::{
    EffectBudget, NativeAdmissionError, NativeScopeAdmissionPort, NetworkScope, PermissionMode,
    ScopeError, admit_invocation_scope,
};
use runne_platform::local_command_linux::LinuxCompositeScopeAdmission;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

#[test]
fn finite_closed_broad_quotas_fail_before_native_namespace_preflight() {
    let protected_dir = tempfile::tempdir().expect("protected control-plane root");
    let protected_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(protected_dir.path())
        .expect("held protected root");
    let admission =
        LinuxCompositeScopeAdmission::new(&[&protected_file]).expect("native admission registry");

    for network in [NetworkScope::None, NetworkScope::BroadSameUser] {
        for value in [0, 1, u64::MAX] {
            for budget in [
                EffectBudget {
                    max_operations: Some(value),
                    max_bytes: None,
                },
                EffectBudget {
                    max_operations: None,
                    max_bytes: Some(value),
                },
            ] {
                let mut scope = none::closed_scope(
                    &admission,
                    network,
                    EffectBudget {
                        max_operations: None,
                        max_bytes: None,
                    },
                );
                scope.budget = budget;
                assert_eq!(
                    scope.validate(),
                    Err(ScopeError::UnsupportedBroadEffectQuota)
                );
                for mode in [
                    PermissionMode::AskAlways,
                    PermissionMode::RiskBased,
                    PermissionMode::FullAccess,
                ] {
                    assert_eq!(
                        admission.admit_mode_readiness(mode, &scope),
                        Err(NativeAdmissionError::CompositePolicyUnenforceable),
                        "readiness must reject before namespace preflight: {network:?} {budget:?} {mode:?}"
                    );
                }
                assert_eq!(
                    admission.admit_scope(&scope),
                    Err(NativeAdmissionError::CompositePolicyUnenforceable),
                    "admission must reject before namespace preflight: {network:?} {budget:?}"
                );
                assert_eq!(
                    admit_invocation_scope(&scope, &admission),
                    Err(NativeAdmissionError::CompositePolicyUnenforceable)
                );
            }
        }
    }
}

#[test]
fn unbudgeted_closed_broad_scopes_admit_both_network_postures() {
    eprintln!("RUN: unbudgeted_closed_broad_scopes_admit_both_network_postures");
    let Some(fixture) = none::fixture() else {
        return;
    };
    for network in [NetworkScope::None, NetworkScope::BroadSameUser] {
        let scope = none::closed_scope(
            &fixture.admission,
            network,
            EffectBudget {
                max_operations: None,
                max_bytes: None,
            },
        );
        scope.validate().unwrap();
        for mode in [
            PermissionMode::AskAlways,
            PermissionMode::RiskBased,
            PermissionMode::FullAccess,
        ] {
            assert!(
                fixture.admission.admit_mode_readiness(mode, &scope).is_ok(),
                "None/None closed broad readiness: {network:?} {mode:?}"
            );
        }
        admit_invocation_scope(&scope, &fixture.admission)
            .expect("None/None closed broad native admission");
    }
    fixture.area.remove();
}

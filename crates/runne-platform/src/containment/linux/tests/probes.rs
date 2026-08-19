//! Probe and attestation unit tests for the Linux containment backend.

use super::super::{
    LinuxContainment, create_landlock_ruleset, native_certificate, probe_cgroups_v2_delegated,
    probe_landlock_abi, probe_seccomp_filter, runtime_probes,
};
use crate::containment::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, RunnerIdentity,
};

#[test]
fn probe_succeeds_when_all_kernel_features_are_available() {
    // На Linux с Landlock, seccomp и cgroups v2 probe должна вернуть Ok.
    // На ядрах без этих возможностей вернёт BackendUnavailable.
    let landlock = probe_landlock_abi().is_some();
    let seccomp = probe_seccomp_filter();
    let cgroups = probe_cgroups_v2_delegated();
    let result = LinuxContainment::probe();
    if landlock && seccomp && cgroups {
        assert!(
            result.is_ok(),
            "all kernel features available, probe should succeed"
        );
    } else {
        assert_eq!(
            result,
            Err(ContainmentError::BackendUnavailable),
            "missing kernel feature should make backend unavailable"
        );
    }
}

#[test]
fn attest_returns_permit_for_valid_linux_certificate() {
    // Формируем сертификат для текущего runner и проверяем,
    // что attestation возвращает Permit.
    let runner = RunnerIdentity::new("test-runner").expect("runner identity");
    let certificate = native_certificate(
        runner.clone(),
        vec![
            ContainmentGate::DirectEgressDenied,
            ContainmentGate::WorkspaceFilesystemConfined,
        ],
    )
    .expect("create certificate");

    let request = ContainmentRequest::new(
        ContainmentBackendId::new("runne-native-linux").unwrap(),
        ContainmentBackendVersion::new("0.1.0").unwrap(),
        HostPlatform::Linux,
        runner,
        vec![
            ContainmentGate::DirectEgressDenied,
            ContainmentGate::WorkspaceFilesystemConfined,
        ],
    )
    .expect("create request");

    let probes = runtime_probes();
    assert_eq!(
        LinuxContainment::attest(&request, Some(&certificate), &probes),
        Ok(AttestationVerdict::Permit),
        "valid Linux certificate should yield Permit"
    );
}

#[test]
fn attest_rejects_non_linux_platform() {
    let certificate = native_certificate(
        RunnerIdentity::new("test-runner").unwrap(),
        vec![ContainmentGate::DirectEgressDenied],
    )
    .expect("create certificate");
    let request = ContainmentRequest::new(
        ContainmentBackendId::new("runne-native-linux").unwrap(),
        ContainmentBackendVersion::new("0.1.0").unwrap(),
        HostPlatform::MacOs,
        RunnerIdentity::new("test-runner").unwrap(),
        vec![ContainmentGate::DirectEgressDenied],
    )
    .expect("create request");

    assert_eq!(
        LinuxContainment::attest(&request, Some(&certificate), &runtime_probes()),
        Err(ContainmentError::BackendUnavailable),
        "Linux backend must reject non-Linux platform"
    );
}

#[test]
fn landlock_abi_probe_reports_capability_or_absence() {
    // На Linux с kernel >= 5.13 должен вернуться Some(abi_version).
    // На старых ядрах или non-Linux target этот тест не собирается
    // (модуль под cfg(target_os = "linux")).
    let result = probe_landlock_abi();
    assert!(
        result.is_none() || result.unwrap() >= 1,
        "Landlock ABI version must be either unavailable or >= 1, got {:?}",
        result
    );
}

#[test]
fn seccomp_filter_probe_reports_availability() {
    // На Linux ядрах с seccomp должен вернуться true.
    // Этот тест собирается только под cfg(target_os = "linux").
    let available = probe_seccomp_filter();
    // Проба не должна паниковать; значение true/false зависит от ядра.
    let _ = available;
}

#[test]
fn cgroups_v2_probe_reports_availability_or_absence() {
    // На Linux с cgroups v2 должен вернуться true или false;
    // на non-Linux этот тест не собирается.
    let _ = probe_cgroups_v2_delegated();
}

#[test]
fn landlock_ruleset_can_be_created_with_abi_v1_rights() {
    // Проверяем, что ядро позволяет создать ruleset с
    // базовыми filesystem access rights ABI v1.
    const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const ACCESS_FS_READ_DIR: u64 = 1 << 3;
    match create_landlock_ruleset(ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR) {
        Ok(fd) => unsafe {
            libc::close(fd);
        },
        Err(ContainmentError::BackendUnavailable) => {
            // Landlock не доступен — это допустимо для старых ядер.
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}

//! Linux containment backend: Landlock, seccomp-bpf and cgroups v2.
//!
//! Platform-specific OS syscalls require `unsafe`; all unsafe blocks are
//! isolated in the [`probes`] submodule with safety comments.

mod probes;

pub use probes::{
    add_landlock_path_rule, create_landlock_ruleset, probe_cgroups_v2_delegated,
    probe_landlock_abi, probe_seccomp_filter, restrict_self_with_landlock,
};

use super::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
    RuntimeProbe,
};

/// Native Linux containment backend.
#[derive(Debug, PartialEq, Eq)]
pub struct LinuxContainment;

const LINUX_BACKEND_ID: &str = "gocode-native-linux";
const LINUX_BACKEND_VERSION: &str = "0.1.0";

impl LinuxContainment {
    /// Возвращает Permit, если сертификат соответствует запросу и платформе Linux.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let certificate = certificate.ok_or(ContainmentError::BackendUnavailable)?;
        if request.platform != HostPlatform::Linux {
            return Err(ContainmentError::BackendUnavailable);
        }
        if !certificate.exactly_covers(request) || !certificate.probes_match(probes) {
            return Err(ContainmentError::BackendUnavailable);
        }
        Ok(AttestationVerdict::Permit)
    }

    /// Проверяет Landlock ABI, seccomp и cgroups v2. Если все probes
    /// успешны, возвращает бэкенд для дальнейшей attestation.
    pub fn probe() -> Result<Self, ContainmentError> {
        let landlock = probe_landlock_abi().is_some();
        let seccomp = probe_seccomp_filter();
        let cgroups = probe_cgroups_v2_delegated();
        if landlock && seccomp && cgroups {
            Ok(LinuxContainment)
        } else {
            Err(ContainmentError::BackendUnavailable)
        }
    }
}

/// Формирует runtime probes из реальных Linux probe-результатов.
///
/// Возвращаются в каноническом порядке по идентификатору (как требует
/// `NativeCertificate::probes_match`).
pub fn runtime_probes() -> Vec<RuntimeProbe> {
    vec![
        RuntimeProbe::new(
            "cgroups-v2-delegated",
            if probe_cgroups_v2_delegated() {
                "available"
            } else {
                "unavailable"
            },
        )
        .expect("cgroups probe id valid"),
        RuntimeProbe::new(
            "landlock-abi",
            probe_landlock_abi()
                .map(|v| format!("abi-{v}"))
                .unwrap_or_else(|| "unavailable".into()),
        )
        .expect("landlock probe id valid"),
        RuntimeProbe::new(
            "seccomp-filter",
            if probe_seccomp_filter() {
                "available"
            } else {
                "unavailable"
            },
        )
        .expect("seccomp probe id valid"),
    ]
}

/// Формирует сертификат qualification для текущего Linux runner.
pub fn native_certificate(
    runner_identity: RunnerIdentity,
    covered_gates: Vec<ContainmentGate>,
) -> Result<NativeCertificate, ContainmentError> {
    let digest = super::combined_probe_digest(&runtime_probes());

    NativeCertificate::new(
        ContainmentBackendId::new(LINUX_BACKEND_ID)?,
        ContainmentBackendVersion::new(LINUX_BACKEND_VERSION)?,
        HostPlatform::Linux,
        runner_identity,
        qualification_date(),
        digest,
        covered_gates,
    )
}

fn qualification_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86_400;
    format!("{days}")
}

#[cfg(test)]
mod tests;

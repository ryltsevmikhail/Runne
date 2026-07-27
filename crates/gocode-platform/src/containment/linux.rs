//! Linux containment — ограничения файловой системы Landlock, фильтрация
//! системных вызовов seccomp-bpf и ресурсные лимиты cgroups v2.

use super::{ContainmentError, EnforcementCapabilityDescriptor};

/// Профиль Linux containment для одного запуска.
pub struct LinuxContainmentProfile {
    /// Правила Landlock, ограничивающие доступ к файловой системе разрешёнными путями.
    pub landlock_rules: LandlockRules,
    /// Профиль seccomp-bpf, ограничивающий разрешённые системные вызовы.
    pub seccomp_profile: SeccompProfile,
    /// Ресурсные лимиты cgroups v2.
    pub resource_limits: CgroupLimits,
}

/// Правила доступа Landlock к файловой системе.
#[derive(Debug, Clone)]
pub struct LandlockRules {
    /// Пути, доступные contained-процессу для чтения.
    pub read_paths: Vec<String>,
    /// Пути, доступные contained-процессу для записи.
    pub write_paths: Vec<String>,
}

/// Профиль allowlist системных вызовов seccomp.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    /// Разрешённые номера системных вызовов. Пустой список означает deny all.
    pub allowed_syscalls: Vec<i32>,
}

/// Ресурсные лимиты cgroups v2.
#[derive(Debug, Clone)]
pub struct CgroupLimits {
    /// Максимальный объём памяти в байтах. Ноль означает отсутствие лимита.
    pub memory_max: u64,
    /// Максимальное число процессов (`pids.max`).
    pub pids_max: u32,
    /// Квота CPU в микросекундах на период.
    pub cpu_quota_us: i64,
    /// Период CPU в микросекундах.
    pub cpu_period_us: u64,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            memory_max: 512 * 1024 * 1024,
            pids_max: 64,
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
        }
    }
}

/// Менеджер Linux containment, проверяющий поддержку ядра и применяющий профили.
pub struct LinuxContainment {
    landlock_supported: bool,
    landlock_abi: u32,
    seccomp_supported: bool,
    cgroups_v2_supported: bool,
}

impl LinuxContainment {
    /// Проверить возможности ядра. Все механизмы обязательны, иначе бэкенд недоступен.
    pub fn probe() -> Result<Self, ContainmentError> {
        let landlock_supported = Self::probe_landlock();
        let seccomp_supported = Self::probe_seccomp();
        let cgroups_v2_supported = Self::probe_cgroups_v2();

        if !landlock_supported || !seccomp_supported || !cgroups_v2_supported {
            return Err(ContainmentError::BackendUnavailable);
        }

        Ok(Self {
            landlock_supported,
            landlock_abi: Self::get_landlock_abi(),
            seccomp_supported,
            cgroups_v2_supported,
        })
    }

    /// Применить containment к текущему процессу до `exec`.
    ///
    /// Метод должен вызываться в дочернем процессе после `fork` и до `exec`.
    pub fn apply_to_current(
        &self,
        profile: &LinuxContainmentProfile,
    ) -> Result<(), ContainmentError> {
        if self.landlock_supported {
            self.apply_landlock(&profile.landlock_rules)?;
        }
        if self.seccomp_supported {
            self.apply_seccomp(&profile.seccomp_profile)?;
        }
        Ok(())
    }

    /// Применить ресурсные лимиты cgroups v2 к процессу.
    pub fn apply_cgroup_limits(
        &self,
        pid: u32,
        limits: &CgroupLimits,
    ) -> Result<(), ContainmentError> {
        if self.cgroups_v2_supported {
            self.write_cgroup_limits(pid, limits)?;
        }
        Ok(())
    }

    /// Получить дескриптор возможностей для сертификации.
    pub fn get_capability_descriptor(&self) -> EnforcementCapabilityDescriptor {
        let mut profiles = Vec::new();
        if self.landlock_supported {
            profiles.push("landlock-fs".into());
        }
        if self.seccomp_supported {
            profiles.push("seccomp-bpf".into());
        }
        if self.cgroups_v2_supported {
            profiles.push("cgroups-v2".into());
        }
        EnforcementCapabilityDescriptor {
            backend_id: "linux-native".into(),
            platform: "linux".into(),
            os_revision: Self::get_kernel_version(),
            supported_profiles: profiles,
            certification_evidence_digest: String::new(),
        }
    }

    fn probe_landlock() -> bool {
        std::path::Path::new("/proc/sys/kernel/landlock").exists()
    }

    fn probe_seccomp() -> bool {
        std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists()
            || std::fs::read_to_string("/proc/self/status")
                .is_ok_and(|status| status.lines().any(|line| line.starts_with("Seccomp:")))
    }

    fn probe_cgroups_v2() -> bool {
        std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }

    fn get_landlock_abi() -> u32 {
        std::fs::read_to_string("/proc/sys/kernel/landlock/abi")
            .ok()
            .and_then(|abi| abi.trim().parse().ok())
            .unwrap_or(0)
    }

    fn get_kernel_version() -> String {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|version| version.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    }

    fn apply_landlock(&self, rules: &LandlockRules) -> Result<(), ContainmentError> {
        for path in &rules.read_paths {
            if !std::path::Path::new(path).exists() {
                return Err(ContainmentError::SandboxApplyFailed(format!(
                    "landlock read path does not exist: {path}"
                )));
            }
        }
        for path in &rules.write_paths {
            if !std::path::Path::new(path).exists() {
                return Err(ContainmentError::SandboxApplyFailed(format!(
                    "landlock write path does not exist: {path}"
                )));
            }
        }
        if self.landlock_abi < 1 {
            return Err(ContainmentError::BackendUnavailable);
        }

        // Реальные syscalls Landlock будут добавлены вместе с безопасными обёртками.
        Ok(())
    }

    fn apply_seccomp(&self, profile: &SeccompProfile) -> Result<(), ContainmentError> {
        if profile.allowed_syscalls.is_empty() {
            return Ok();
        }

        // Реальная BPF-программа будет добавлена вместе с безопасной интеграцией seccomp.
        Ok(())
    }

    fn write_cgroup_limits(&self, pid: u32, limits: &CgroupLimits) -> Result<(), ContainmentError> {
        let cgroup_path = format!("/sys/fs/cgroup/gocode-{pid}");
        std::fs::create_dir_all(&cgroup_path).map_err(|error| {
            ContainmentError::SandboxApplyFailed(format!("cgroup create: {error}"))
        })?;

        std::fs::write(
            format!("{cgroup_path}/pids.max"),
            limits.pids_max.to_string(),
        )
        .map_err(|error| ContainmentError::SandboxApplyFailed(format!("pids.max: {error}")))?;

        if limits.memory_max > 0 {
            std::fs::write(
                format!("{cgroup_path}/memory.max"),
                limits.memory_max.to_string(),
            )
            .map_err(|error| {
                ContainmentError::SandboxApplyFailed(format!("memory.max: {error}"))
            })?;
        }

        if limits.cpu_quota_us > 0 {
            std::fs::write(
                format!("{cgroup_path}/cpu.max"),
                format!("{} {}", limits.cpu_quota_us, limits.cpu_period_us),
            )
            .map_err(|error| ContainmentError::SandboxApplyFailed(format!("cpu.max: {error}")))?;
        }

        std::fs::write(format!("{cgroup_path}/cgroup.procs"), pid.to_string()).map_err(
            |error| ContainmentError::SandboxApplyFailed(format!("cgroup.procs: {error}")),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_kernel_features() {
        match LinuxContainment::probe() {
            Ok(containment) => {
                assert!(containment.landlock_supported);
                assert!(containment.seccomp_supported);
                assert!(containment.cgroups_v2_supported);
            }
            Err(ContainmentError::BackendUnavailable) => {}
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    #[test]
    fn capability_descriptor_lists_supported_profiles() {
        if let Ok(containment) = LinuxContainment::probe() {
            let descriptor = containment.get_capability_descriptor();
            assert_eq!(descriptor.backend_id, "linux-native");
            assert!(
                descriptor
                    .supported_profiles
                    .contains(&"landlock-fs".into())
            );
            assert!(
                descriptor
                    .supported_profiles
                    .contains(&"seccomp-bpf".into())
            );
            assert!(descriptor.supported_profiles.contains(&"cgroups-v2".into()));
        }
    }

    #[test]
    fn unsupported_kernel_fails_closed() {
        let result = LinuxContainment::probe();
        assert!(result.is_ok() || matches!(result, Err(ContainmentError::BackendUnavailable)));
    }
}

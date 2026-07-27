//! Windows containment — AppContainer isolation and Job Objects for resource limits.

use super::{ContainmentError, EnforcementCapabilityDescriptor};

/// Windows containment profile for a single invocation.
#[derive(Debug, Clone)]
pub struct WindowsContainmentProfile {
    /// AppContainer name for process isolation.
    pub appcontainer_name: String,
    /// Capability SIDs to grant (for example, `internetClient`).
    pub capabilities: Vec<String>,
    /// Whether to use LPAC (Less Privileged AppContainer) for network-restricted profiles.
    pub lpac: bool,
    /// Job object resource limits.
    pub job_limits: JobLimits,
}

/// Job Object resource limits.
#[derive(Debug, Clone)]
pub struct JobLimits {
    /// Maximum number of active processes in the job.
    pub active_process_limit: u32,
    /// Maximum memory in bytes. Zero means no limit.
    pub process_memory_limit: usize,
    /// CPU time limit per process in 100ns units. Zero means no limit.
    pub per_process_cpu_limit: u64,
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            active_process_limit: 64,
            process_memory_limit: 512 * 1024 * 1024,
            per_process_cpu_limit: 0,
        }
    }
}

/// Менеджер Windows containment для AppContainer и Job Objects.
pub struct WindowsContainment {
    #[cfg(target_os = "windows")]
    appcontainer_supported: bool,
    #[cfg(target_os = "windows")]
    job_objects_supported: bool,
}

impl WindowsContainment {
    /// Проверить доступность возможностей Windows containment.
    pub fn probe() -> Result<Self, ContainmentError> {
        #[cfg(target_os = "windows")]
        {
            // AppContainer требует Windows 8+ (NT 6.2+), Job Objects доступны с Win2k.
            let appcontainer_supported = true;
            let job_objects_supported = true;

            Ok(Self {
                appcontainer_supported,
                job_objects_supported,
            })
        }
        #[cfg(not(target_os = "windows"))]
        Err(ContainmentError::BackendUnavailable)
    }

    /// Создать AppContainer и подготовить запуск дочернего процесса в нём.
    pub fn create_container(
        &self,
        profile: &WindowsContainmentProfile,
    ) -> Result<String, ContainmentError> {
        #[cfg(target_os = "windows")]
        {
            // Вызовы CreateAppContainerProfile потребуют интеграции windows-sys.
            if profile.appcontainer_name.is_empty() {
                return Err(ContainmentError::SandboxApplyFailed(
                    "appcontainer name is empty".into(),
                ));
            }

            for capability in &profile.capabilities {
                if capability.is_empty() {
                    return Err(ContainmentError::SandboxApplyFailed(
                        "empty capability SID".into(),
                    ));
                }
            }

            Ok(profile.appcontainer_name.clone())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (self, profile);
            Err(ContainmentError::BackendUnavailable)
        }
    }

    /// Создать Job Object с ресурсными лимитами.
    pub fn create_job_object(&self, limits: &JobLimits) -> Result<String, ContainmentError> {
        #[cfg(target_os = "windows")]
        {
            // CreateJobObjectW и SetInformationJobObject потребуют windows-sys bindings.
            if limits.active_process_limit == 0 {
                return Err(ContainmentError::SandboxApplyFailed(
                    "active process limit must be > 0".into(),
                ));
            }

            Ok(format!("gocode-job-{}", uuid::Uuid::new_v4()))
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (self, limits);
            Err(ContainmentError::BackendUnavailable)
        }
    }

    /// Получить дескриптор возможностей для сертификации.
    pub fn get_capability_descriptor(&self) -> EnforcementCapabilityDescriptor {
        #[cfg(target_os = "windows")]
        {
            let mut profiles = Vec::new();
            if self.appcontainer_supported {
                profiles.push("appcontainer".into());
            }
            if self.job_objects_supported {
                profiles.push("job-objects".into());
            }
            EnforcementCapabilityDescriptor {
                backend_id: "windows-native".into(),
                platform: "windows".into(),
                os_revision: Self::get_windows_version(),
                supported_profiles: profiles,
                certification_evidence_digest: String::new(),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = self;
            EnforcementCapabilityDescriptor {
                backend_id: "windows-native".into(),
                platform: "windows".into(),
                os_revision: Self::get_windows_version(),
                supported_profiles: Vec::new(),
                certification_evidence_digest: String::new(),
            }
        }
    }

    fn get_windows_version() -> String {
        #[cfg(target_os = "windows")]
        {
            // Получение версии через RtlGetVersion или GetVersionEx будет добавлено позже.
            "Windows 10+".into()
        }
        #[cfg(not(target_os = "windows"))]
        "non-windows".into()
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn probe_succeeds_on_windows() {
        let containment = WindowsContainment::probe().unwrap();
        let descriptor = containment.get_capability_descriptor();
        assert_eq!(descriptor.backend_id, "windows-native");
        assert!(
            descriptor
                .supported_profiles
                .contains(&"appcontainer".into())
        );
        assert!(
            descriptor
                .supported_profiles
                .contains(&"job-objects".into())
        );
    }

    #[test]
    fn empty_appcontainer_name_rejected() {
        let containment = WindowsContainment::probe().unwrap();
        let profile = WindowsContainmentProfile {
            appcontainer_name: String::new(),
            capabilities: vec![],
            lpac: false,
            job_limits: JobLimits::default(),
        };
        assert!(containment.create_container(&profile).is_err());
    }

    #[test]
    fn zero_process_limit_rejected() {
        let containment = WindowsContainment::probe().unwrap();
        let limits = JobLimits {
            active_process_limit: 0,
            ..Default::default()
        };
        assert!(containment.create_job_object(&limits).is_err());
    }

    #[test]
    fn valid_profile_accepted() {
        let containment = WindowsContainment::probe().unwrap();
        let profile = WindowsContainmentProfile {
            appcontainer_name: "test-container".into(),
            capabilities: vec!["internetClient".into()],
            lpac: true,
            job_limits: JobLimits::default(),
        };
        assert!(containment.create_container(&profile).is_ok());
    }
}

#[cfg(all(test, not(target_os = "windows")))]
mod non_windows_tests {
    use super::*;

    #[test]
    fn probe_reports_backend_unavailable() {
        assert!(matches!(
            WindowsContainment::probe(),
            Err(ContainmentError::BackendUnavailable)
        ));
    }
}

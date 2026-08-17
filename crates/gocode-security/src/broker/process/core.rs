use std::collections::HashMap;
use std::path::Path;

use gocode_platform::containment::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPolicy {
    StructuredOnly,
    Forbidden,
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub executable: String,
    pub executable_digest: Option<[u8; 32]>,
    pub argv: Vec<String>,
    pub env: HashMap<String, String>,
    pub allowed_env_keys: Vec<String>,
    pub inherit_environment: bool,
    pub cwd: String,
    pub authorized_cwd: Option<String>,
    pub cleanup_reservation_id: Option<String>,
    pub worker_generation: u64,
    pub expected_generation: u64,
    pub timeout_ms: u64,
    pub command_policy: CommandPolicy,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcessError {
    #[error("shell command forbidden in structured mode")]
    ShellCommandForbidden,
    #[error("secret in argv")]
    SecretInArgv,
    #[error("cleanup reservation missing")]
    CleanupReservationMissing,
    #[error("sandbox unavailable")]
    SandboxUnavailable,
    #[error("executable not found")]
    ExecutableNotFound,
    #[error("executable identity is invalid")]
    InvalidExecutableIdentity,
    #[error("process argv exceeds its bound")]
    ArgvTooLarge,
    #[error("ambient environment inheritance is forbidden")]
    AmbientEnvironmentForbidden,
    #[error("environment entry is not allowlisted")]
    EnvironmentNotAllowed,
    #[error("working directory is not authorized")]
    CwdNotAuthorized,
    #[error("worker generation is stale")]
    StaleGeneration,
    #[error("process timeout is invalid")]
    InvalidTimeout,
    #[error("containment unavailable")]
    ContainmentUnavailable,
    #[error("containment admission failed: {0}")]
    Containment(#[source] ContainmentError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchedProcess;

pub trait ProcessLauncher {
    fn launch(&self, spec: &ProcessSpec) -> Result<LaunchedProcess, ProcessError>;
}

pub struct ProcessBroker {
    default_policy: CommandPolicy,
}

impl ProcessBroker {
    pub fn new(policy: CommandPolicy) -> Self {
        Self {
            default_policy: policy,
        }
    }

    pub fn validate_spec(&self, spec: &ProcessSpec) -> Result<(), ProcessError> {
        if matches!(self.default_policy, CommandPolicy::Forbidden)
            || matches!(spec.command_policy, CommandPolicy::Forbidden)
        {
            return Err(ProcessError::ShellCommandForbidden);
        }
        if spec.executable.is_empty()
            || spec.executable.len() > 4_096
            || !Path::new(&spec.executable).is_absolute()
            || spec.executable_digest.is_none()
        {
            return Err(ProcessError::InvalidExecutableIdentity);
        }
        if spec.argv.len() > 256
            || spec
                .argv
                .iter()
                .try_fold(0_usize, |total, value| total.checked_add(value.len()))
                .is_none_or(|total| total > 65_536)
        {
            return Err(ProcessError::ArgvTooLarge);
        }
        if spec.inherit_environment {
            return Err(ProcessError::AmbientEnvironmentForbidden);
        }
        if !spec
            .allowed_env_keys
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            || spec
                .env
                .keys()
                .any(|key| spec.allowed_env_keys.binary_search(key).is_err())
        {
            return Err(ProcessError::EnvironmentNotAllowed);
        }
        if spec.authorized_cwd.as_deref() != Some(spec.cwd.as_str())
            || !Path::new(&spec.cwd).is_absolute()
        {
            return Err(ProcessError::CwdNotAuthorized);
        }
        if spec
            .cleanup_reservation_id
            .as_deref()
            .is_none_or(|value| value.is_empty() || value.len() > 256)
        {
            return Err(ProcessError::CleanupReservationMissing);
        }
        if spec.worker_generation != spec.expected_generation {
            return Err(ProcessError::StaleGeneration);
        }
        if spec.timeout_ms == 0 || spec.timeout_ms > 86_400_000 {
            return Err(ProcessError::InvalidTimeout);
        }
        if matches!(spec.command_policy, CommandPolicy::StructuredOnly) {
            if Path::new(&spec.executable)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase)
                .is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "sh" | "bash"
                            | "zsh"
                            | "fish"
                            | "cmd"
                            | "cmd.exe"
                            | "powershell"
                            | "powershell.exe"
                            | "pwsh"
                            | "pwsh.exe"
                    )
                })
            {
                return Err(ProcessError::ShellCommandForbidden);
            }
            for argument in &spec.argv {
                if argument.contains(';')
                    || argument.contains('|')
                    || argument.contains('$')
                    || argument.contains('`')
                {
                    return Err(ProcessError::ShellCommandForbidden);
                }
            }
        }
        for argument in &spec.argv {
            let lower = argument.to_lowercase();
            if lower.starts_with("sk-") || lower.contains("token=") || lower.contains("secret=") {
                return Err(ProcessError::SecretInArgv);
            }
        }
        Ok(())
    }

    pub fn prepare_contained(
        &self,
        spec: &ProcessSpec,
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
        launcher: &dyn ProcessLauncher,
    ) -> Result<LaunchedProcess, ProcessError> {
        self.validate_spec(spec)?;
        match current_platform_admission(request, certificate, probes) {
            Ok(()) => {}
            Err(ContainmentError::BackendUnavailable) => {
                return Err(ProcessError::ContainmentUnavailable);
            }
            Err(error) => return Err(ProcessError::Containment(error)),
        }
        launcher.launch(spec)
    }
}

fn current_platform_admission(
    request: &ContainmentRequest,
    certificate: Option<&NativeCertificate>,
    probes: &[RuntimeProbe],
) -> Result<(), ContainmentError> {
    #[cfg(target_os = "linux")]
    let verdict = gocode_platform::containment::linux::LinuxContainment::attest(
        request,
        certificate,
        probes,
    )?;
    #[cfg(target_os = "macos")]
    let verdict = gocode_platform::containment::macos::MacOsContainment::attest(
        request,
        certificate,
        probes,
    )?;
    #[cfg(target_os = "windows")]
    let verdict = gocode_platform::containment::windows::WindowsContainment::attest(
        request,
        certificate,
        probes,
    )?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (request, certificate, probes);
        return Err(ContainmentError::BackendUnavailable);
    }

    match verdict {
        AttestationVerdict::Unavailable => Err(ContainmentError::BackendUnavailable),
        AttestationVerdict::Permit => Ok(()),
    }
}

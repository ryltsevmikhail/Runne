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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_executable() -> String {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn absolute_cwd() -> String {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn absolute_shell() -> String {
        #[cfg(windows)]
        {
            r"C:\Windows\System32\cmd.exe".into()
        }
        #[cfg(not(windows))]
        {
            "/bin/sh".into()
        }
    }

    #[test]
    fn shell_metacharacters_rejected() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let cwd = absolute_cwd();
        let spec = ProcessSpec {
            executable: absolute_shell(),
            executable_digest: Some([1; 32]),
            argv: vec!["-c".into(), "rm -rf /".into()],
            env: HashMap::new(),
            allowed_env_keys: Vec::new(),
            inherit_environment: false,
            cwd: cwd.clone(),
            authorized_cwd: Some(cwd),
            cleanup_reservation_id: Some("cleanup-1".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        };
        assert!(broker.validate_spec(&spec).is_err());
    }

    #[test]
    fn secret_in_argv_rejected() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let cwd = absolute_cwd();
        let spec = ProcessSpec {
            executable: absolute_executable(),
            executable_digest: Some([1; 32]),
            argv: vec!["--token".into(), "sk-abc123".into()],
            env: HashMap::new(),
            allowed_env_keys: Vec::new(),
            inherit_environment: false,
            cwd: cwd.clone(),
            authorized_cwd: Some(cwd),
            cleanup_reservation_id: Some("cleanup-1".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        };
        assert!(matches!(
            broker.validate_spec(&spec),
            Err(ProcessError::SecretInArgv)
        ));
    }

    #[test]
    fn valid_spec_accepted() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let cwd = absolute_cwd();
        let spec = ProcessSpec {
            executable: absolute_executable(),
            executable_digest: Some([1; 32]),
            argv: vec!["--input".into(), "file.txt".into()],
            env: HashMap::from([("HOME".into(), "/var/empty".into())]),
            allowed_env_keys: vec!["HOME".into()],
            inherit_environment: false,
            cwd: cwd.clone(),
            authorized_cwd: Some(cwd),
            cleanup_reservation_id: Some("cleanup-1".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        };
        assert!(broker.validate_spec(&spec).is_ok());
    }

    #[test]
    fn exact_executable_and_ambient_context_are_required() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let mut spec = valid_spec();
        spec.executable = "tool".into();
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::InvalidExecutableIdentity)
        );

        let mut spec = valid_spec();
        spec.executable_digest = None;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::InvalidExecutableIdentity)
        );

        let mut spec = valid_spec();
        spec.inherit_environment = true;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::AmbientEnvironmentForbidden)
        );

        let mut spec = valid_spec();
        spec.env.insert("PATH".into(), "/tmp/bin".into());
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::EnvironmentNotAllowed)
        );
    }

    #[test]
    fn cwd_cleanup_generation_and_timeout_fail_closed() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let mut spec = valid_spec();
        spec.authorized_cwd = None;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::CwdNotAuthorized)
        );

        let mut spec = valid_spec();
        spec.cleanup_reservation_id = None;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::CleanupReservationMissing)
        );

        let mut spec = valid_spec();
        spec.expected_generation = 2;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::StaleGeneration)
        );

        let mut spec = valid_spec();
        spec.timeout_ms = 0;
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::InvalidTimeout)
        );
    }

    #[test]
    fn argv_is_bounded_and_absolute_shells_are_forbidden() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let mut spec = valid_spec();
        spec.argv = vec!["x".into(); 257];
        assert_eq!(broker.validate_spec(&spec), Err(ProcessError::ArgvTooLarge));

        let mut spec = valid_spec();
        spec.executable = absolute_shell();
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::ShellCommandForbidden)
        );
    }

    fn valid_spec() -> ProcessSpec {
        let cwd = absolute_cwd();
        ProcessSpec {
            executable: absolute_executable(),
            executable_digest: Some([1; 32]),
            argv: vec!["--input".into(), "file.txt".into()],
            env: HashMap::from([("HOME".into(), "/var/empty".into())]),
            allowed_env_keys: vec!["HOME".into()],
            inherit_environment: false,
            cwd: cwd.clone(),
            authorized_cwd: Some(cwd),
            cleanup_reservation_id: Some("cleanup-1".into()),
            worker_generation: 1,
            expected_generation: 1,
            timeout_ms: 1_000,
            command_policy: CommandPolicy::StructuredOnly,
        }
    }
}

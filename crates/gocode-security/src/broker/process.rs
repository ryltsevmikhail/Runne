use std::collections::HashMap;

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
    pub argv: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: String,
    pub command_policy: CommandPolicy,
}

#[derive(Debug, thiserror::Error)]
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
        if matches!(spec.command_policy, CommandPolicy::StructuredOnly) {
            if matches!(spec.executable.as_str(), "sh" | "bash" | "zsh" | "fish") {
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

    #[test]
    fn shell_metacharacters_rejected() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let spec = ProcessSpec {
            executable: "sh".into(),
            argv: vec!["-c".into(), "rm -rf /".into()],
            env: HashMap::new(),
            cwd: "/tmp".into(),
            command_policy: CommandPolicy::StructuredOnly,
        };
        assert!(broker.validate_spec(&spec).is_err());
    }

    #[test]
    fn secret_in_argv_rejected() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let spec = ProcessSpec {
            executable: "tool".into(),
            argv: vec!["--token".into(), "sk-abc123".into()],
            env: HashMap::new(),
            cwd: "/tmp".into(),
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
        let spec = ProcessSpec {
            executable: "/usr/bin/tool".into(),
            argv: vec!["--input".into(), "file.txt".into()],
            env: HashMap::from([("HOME".into(), "/var/empty".into())]),
            cwd: "/tmp".into(),
            command_policy: CommandPolicy::StructuredOnly,
        };
        assert!(broker.validate_spec(&spec).is_ok());
    }
}

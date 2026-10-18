#[cfg(test)]
mod tests {
    use super::*;

    fn virtual_executable() -> String {
        #[cfg(windows)]
        {
            r"C:\virtual\bin\tool.exe".into()
        }
        #[cfg(not(windows))]
        {
            "/virtual/bin/tool".into()
        }
    }

    fn virtual_cwd() -> String {
        #[cfg(windows)]
        {
            r"C:\virtual\workspace".into()
        }
        #[cfg(not(windows))]
        {
            "/virtual/workspace".into()
        }
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
        let cwd = virtual_cwd();
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
        let cwd = virtual_cwd();
        let spec = ProcessSpec {
            executable: virtual_executable(),
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
        let cwd = virtual_cwd();
        let spec = ProcessSpec {
            executable: virtual_executable(),
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

    #[test]
    fn structured_mode_rejects_bash_zsh_and_powershell_aliases() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        for alias in [
            "bash",
            "BASH",
            "zsh",
            "ZSH",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
        ] {
            let mut spec = valid_spec();
            let separator = if cfg!(windows) { '\\' } else { '/' };
            spec.executable = format!("{}{separator}{alias}", virtual_cwd());
            assert_eq!(
                broker.validate_spec(&spec),
                Err(ProcessError::ShellCommandForbidden),
                "StructuredOnly must reject the {alias} shell alias"
            );
        }
    }

    #[test]
    fn structured_argv_rejects_control_bytes_and_redirect_delimiters() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        for argument in [
            "line\nbreak",
            "line\rbreak",
            "nul\0byte",
            "delete\u{7f}byte",
            "first;second",
            "first|second",
            "$(touch marker)",
            "`touch marker`",
            "output > file",
            "input < file",
            "left & right",
        ] {
            let mut spec = valid_spec();
            spec.argv = vec![argument.into()];
            assert_eq!(
                broker.validate_spec(&spec),
                Err(ProcessError::ShellCommandForbidden),
                "structured argv must reject {argument:?}"
            );
        }
    }

    #[test]
    fn structured_argv_accepts_literal_unicode_brackets_and_quotes() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let mut spec = valid_spec();
        spec.argv = vec![
            "--value".into(),
            "café [square] {curly} 'single' \"double\"".into(),
        ];
        assert_eq!(broker.validate_spec(&spec), Ok(()));
    }

    #[test]
    fn structured_environment_is_bounded() {
        let broker = ProcessBroker::new(CommandPolicy::StructuredOnly);
        let mut spec = valid_spec();
        spec.allowed_env_keys = (0..65).map(|index| format!("K{index:02}")).collect();
        spec.env = spec
            .allowed_env_keys
            .iter()
            .map(|key| (key.clone(), "value".into()))
            .collect();
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::EnvironmentTooLarge)
        );

        let mut spec = valid_spec();
        spec.allowed_env_keys = (0..64)
            .map(|index| format!("K{index:02}{}", "x".repeat(2_048)))
            .collect();
        assert_eq!(
            broker.validate_spec(&spec),
            Err(ProcessError::EnvironmentTooLarge)
        );
    }

    fn valid_spec() -> ProcessSpec {
        let cwd = virtual_cwd();
        ProcessSpec {
            executable: virtual_executable(),
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

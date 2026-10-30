fn run_entrypoint(arguments: Vec<OsString>) -> ProcessOutcome {
    if tui_backend::selected(&arguments) {
        return tui_backend::entry(arguments);
    }
    #[cfg(target_os = "linux")]
    if linux_cli_credential_host::selected(&arguments) {
        return linux_cli_credential_host::run();
    }
    #[cfg(all(target_os = "macos", feature = "persistent-reference-probe"))]
    if persistent_reference_probe::selected(&arguments) {
        return persistent_reference_probe::outcome();
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1)
    {
        return broker_process_outcome(run_provider_credential_broker(VecDeque::from(arguments)));
    }
    #[cfg(target_os = "linux")]
    if arguments
        .iter()
        .any(|argument| argument == "--protected-runtime-root")
    {
        return protected_runtime_ui::run(arguments);
    }
    let result = tokio::runtime::Runtime::new()
        .map_or((Err(CliError::Runtime), OutputFormat::Text), |runtime| {
            runtime.block_on(run_after_broker_bootstrap(arguments))
        });
    process_outcome(result.0, result.1)
}

fn broker_process_outcome(result: Result<(), CliError>) -> ProcessOutcome {
    match result {
        Ok(()) => ProcessOutcome {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(error) => process_outcome(Err(error), OutputFormat::Text),
    }
}

fn parse_global_options(arguments: Vec<OsString>) -> Result<CliState, CliError> {
    let mut arguments = VecDeque::from(arguments);
    let mut format = None;
    let mut remaining = Vec::new();

    while let Some(arg) = arguments.pop_front() {
        if arg == "--format" {
            let value = arguments.pop_front().ok_or(CliError::Usage)?;
            let parsed = value
                .to_str()
                .and_then(OutputFormat::parse)
                .ok_or(CliError::Usage)?;
            if format.replace(parsed).is_some() {
                return Err(CliError::Usage);
            }
        } else if let Some(s) = arg.to_str() {
            if let Some(value) = s.strip_prefix("--format=") {
                let parsed = OutputFormat::parse(value).ok_or(CliError::Usage)?;
                if format.replace(parsed).is_some() {
                    return Err(CliError::Usage);
                }
            } else {
                remaining.push(arg);
            }
        } else {
            remaining.push(arg);
        }
    }

    Ok(CliState {
        format: format.unwrap_or_default(),
        arguments: remaining,
    })
}

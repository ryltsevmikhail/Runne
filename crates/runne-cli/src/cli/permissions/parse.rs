fn parse_permissions(
    mut arguments: VecDeque<OsString>,
) -> Result<ParsedPermissionsCommand, CliError> {
    let group = pop_string(&mut arguments)?;
    if group == "--help" || group == "-h" {
        return Err(CliError::Help(PERMISSIONS_HELP.to_owned()));
    }

    match group.as_str() {
        "status" => {
            if peek(&arguments).is_some_and(|arg| arg == "--help" || arg == "-h") {
                return Err(CliError::Help(PERMISSIONS_STATUS_HELP.to_owned()));
            }
            expect_token(&mut arguments, "--workspace-id")?;
            let workspace_id = parse_id(&pop_string(&mut arguments)?)?;
            expect_end(&arguments)?;
            Ok(ParsedPermissionsCommand::Read(PermissionsCommand::Status {
                workspace_id,
            }))
        }
        "command" => {
            let operation = pop_string(&mut arguments)?;
            if operation == "--help" || operation == "-h" {
                return Err(CliError::Help(PERMISSIONS_COMMAND_STATUS_HELP.to_owned()));
            }
            if operation != "status" {
                return Err(CliError::Usage);
            }
            if peek(&arguments).is_some_and(|arg| arg == "--help" || arg == "-h") {
                return Err(CliError::Help(PERMISSIONS_COMMAND_STATUS_HELP.to_owned()));
            }
            expect_token(&mut arguments, "--workspace-id")?;
            let workspace_id = parse_id(&pop_string(&mut arguments)?)?;
            expect_token(&mut arguments, "--command-id")?;
            let command_id = parse_id(&pop_string(&mut arguments)?)?;
            expect_end(&arguments)?;
            Ok(ParsedPermissionsCommand::Read(
                PermissionsCommand::CommandStatus {
                    workspace_id,
                    command_id,
                },
            ))
        }
        "approvals" => {
            let operation = pop_string(&mut arguments)?;
            if operation == "--help" || operation == "-h" {
                return Err(CliError::Help(PERMISSIONS_APPROVALS_HELP.to_owned()));
            }
            match operation.as_str() {
                "list" => {
                    if peek(&arguments).is_some_and(|arg| arg == "--help" || arg == "-h") {
                        return Err(CliError::Help(PERMISSIONS_APPROVALS_LIST_HELP.to_owned()));
                    }
                    expect_end(&arguments)?;
                    Ok(ParsedPermissionsCommand::Read(
                        PermissionsCommand::ApprovalsList,
                    ))
                }
                "respond" => parse_approval_response_command(arguments)
                    .map(ParsedPermissionsCommand::ApprovalRespond),
                _ => Err(CliError::Usage),
            }
        }
        "mode" => parse_permission_mode_command(arguments).map(ParsedPermissionsCommand::ModeSet),
        _ => Err(CliError::Usage),
    }
}

fn parse_approval_response_command(
    mut arguments: VecDeque<OsString>,
) -> Result<ApprovalResponseIntent, CliError> {
    if peek(&arguments).is_some_and(|arg| arg == "--help" || arg == "-h") {
        return Err(CliError::Help(
            PERMISSIONS_APPROVALS_RESPOND_HELP.to_owned(),
        ));
    }
    expect_token(&mut arguments, "--approval-id")?;
    let approval_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--decision")?;
    let decision = match pop_string(&mut arguments)?.as_str() {
        "approve" => runne_runtime_client::ApprovalDecisionDto::Approve,
        "deny" => runne_runtime_client::ApprovalDecisionDto::Deny,
        _ => return Err(CliError::Usage),
    };
    expect_token(&mut arguments, "--command-id")?;
    let command_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--idempotency-key")?;
    let idempotency_key = pop_string(&mut arguments)?;
    runne_runtime_client::CommandIdentity::new(command_id, idempotency_key.clone())
        .map_err(|_| CliError::Usage)?;
    expect_end(&arguments)?;
    Ok(ApprovalResponseIntent {
        approval_id,
        command_id,
        idempotency_key,
        decision,
    })
}

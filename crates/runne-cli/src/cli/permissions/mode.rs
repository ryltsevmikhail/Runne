#[derive(Clone, Debug, Eq, PartialEq)]
struct PermissionModeSetIntent {
    workspace_id: CanonicalId,
    command_id: CanonicalId,
    idempotency_key: String,
    requested_mode: runne_runtime_client::PermissionModeV1,
    expected_authorization_revision: u64,
    preset_version: u16,
    expires_at_unix_ms: Option<i64>,
}

enum ParsedPermissionsCommand {
    Read(PermissionsCommand),
    ModeSet(PermissionModeSetIntent),
    ApprovalRespond(ApprovalResponseIntent),
}

fn parse_permission_mode_command(
    mut arguments: VecDeque<OsString>,
) -> Result<PermissionModeSetIntent, CliError> {
    let operation = pop_string(&mut arguments)?;
    if operation == "--help" || operation == "-h" {
        return Err(CliError::Help(PERMISSIONS_MODE_SET_HELP.to_owned()));
    }
    if operation != "set" {
        return Err(CliError::Usage);
    }
    if peek(&arguments).is_some_and(|arg| arg == "--help" || arg == "-h") {
        return Err(CliError::Help(PERMISSIONS_MODE_SET_HELP.to_owned()));
    }
    expect_token(&mut arguments, "--workspace-id")?;
    let workspace_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--command-id")?;
    let command_id = parse_id(&pop_string(&mut arguments)?)?;
    expect_token(&mut arguments, "--idempotency-key")?;
    let idempotency_key = pop_string(&mut arguments)?;
    runne_runtime_client::CommandIdentity::new(command_id, idempotency_key.clone())
        .map_err(|_| CliError::Usage)?;
    expect_token(&mut arguments, "--mode")?;
    let requested_mode = match pop_string(&mut arguments)?.as_str() {
        "ask_always" => runne_runtime_client::PermissionModeV1::AskAlways,
        "risk_based" => runne_runtime_client::PermissionModeV1::RiskBased,
        "full_access" => runne_runtime_client::PermissionModeV1::FullAccess,
        _ => return Err(CliError::Usage),
    };
    expect_token(&mut arguments, "--expected-revision")?;
    let expected_authorization_revision = pop_string(&mut arguments)?
        .parse::<u64>()
        .map_err(|_| CliError::Usage)?;
    expect_token(&mut arguments, "--preset-version")?;
    let preset_version = pop_string(&mut arguments)?
        .parse::<u16>()
        .map_err(|_| CliError::Usage)?;
    if preset_version != 1 {
        return Err(CliError::Usage);
    }
    expect_token(&mut arguments, "--expires-at-unix-ms")?;
    let expires_at_unix_ms = match pop_string(&mut arguments)?.as_str() {
        "none" => None,
        value => {
            let expiry = value.parse::<i64>().map_err(|_| CliError::Usage)?;
            (expiry > 0)
                .then_some(expiry)
                .ok_or(CliError::Usage)
                .map(Some)?
        }
    };
    expect_end(&arguments)?;
    Ok(PermissionModeSetIntent {
        workspace_id,
        command_id,
        idempotency_key,
        requested_mode,
        expected_authorization_revision,
        preset_version,
        expires_at_unix_ms,
    })
}

#[expect(
    clippy::future_not_send,
    reason = "the CLI polls this command future inline and its runtime adapter remains local"
)]
async fn execute_permission_mode_set<R: PermissionModeRuntime>(
    runtime: &R,
    intent: PermissionModeSetIntent,
) -> Result<CommandOutput, CliError> {
    #[cfg(target_os = "linux")]
    {
        let state = dirs::state_dir().ok_or(CliError::PermissionRecoveryIo(intent.command_id))?;
        let index = DurablePermissionRecoveryIndex::new(state);
        execute_mode_set_with_index(runtime, intent, &index).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime;
        Err(CliError::PermissionRecoveryIo(intent.command_id))
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the CLI polls this command future inline and its runtime and recovery adapters remain local"
)]
async fn execute_mode_set_with_index<R: PermissionModeRuntime, I: PermissionRecoveryIndex>(
    runtime: &R,
    intent: PermissionModeSetIntent,
    index: &I,
) -> Result<CommandOutput, CliError> {
    let command_id = intent.command_id;
    let workspace_id = intent.workspace_id;
    let stable = StableRuntimeIdentity::from_session(runtime.session_info())
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    let audit = RuntimeAuditSnapshot::from_session(runtime.session_info())
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))?;
    let scope = scope_digest(&stable);
    let request = mode_request(&intent)?;
    request.clone().validate().map_err(|_| CliError::Usage)?;

    if let Some(bytes) = index
        .read_existing(&scope, command_id)
        .map_err(|error| recovery_cli_error(command_id, error))?
    {
        let record = decode_mode_recovery_record(&bytes, command_id)?;
        match_recovery_record(&record, &intent, &stable)?;
        require_mode_contract(runtime, workspace_id, command_id).await?;
        let status = read_mode_command(runtime, workspace_id, command_id).await?;
        return render_validated_mode_status(status, &intent);
    }

    require_mode_contract(runtime, workspace_id, command_id).await?;
    let bytes = make_recovery_record(&intent, stable.clone(), audit)
        .map_err(|error| recovery_cli_error(command_id, error))?;
    match index
        .create_exclusive(&scope, command_id, &bytes)
        .map_err(|error| recovery_cli_error(command_id, error))?
    {
        RecordCreateResult::DurableCreated => {
            match runtime.request_permission_mode_change(request).await {
                Ok(status) => render_validated_mode_status(status, &intent),
                Err(ModeApiError::UnknownAfterSend) => {
                    let status = read_mode_command(runtime, workspace_id, command_id).await?;
                    render_validated_mode_status(status, &intent)
                }
                Err(ModeApiError::Api(error)) => Err(CliError::Api(error)),
                Err(ModeApiError::NotFound) => Err(CliError::PermissionCommandUnknown(command_id)),
            }
        }
        RecordCreateResult::Existing(existing) => {
            let record = decode_mode_recovery_record(&existing, command_id)?;
            match_recovery_record(&record, &intent, &stable)?;
            let status = read_mode_command(runtime, workspace_id, command_id).await?;
            render_validated_mode_status(status, &intent)
        }
    }
}

fn mode_request(
    intent: &PermissionModeSetIntent,
) -> Result<runne_runtime_client::PermissionModeChangeRequestV1, CliError> {
    serde_json::from_value(serde_json::json!({
        "workspaceId": canonical_id_bytes(intent.workspace_id)?,
        "commandId": canonical_id_bytes(intent.command_id)?,
        "idempotencyKey": intent.idempotency_key,
        "expectedAuthorizationRevision": intent.expected_authorization_revision,
        "requestedMode": intent.requested_mode,
        "presetVersion": intent.preset_version,
        "expiresAtUnixMs": intent.expires_at_unix_ms,
    }))
    .map_err(|_| CliError::Usage)
}

fn canonical_id_bytes(id: CanonicalId) -> Result<[u8; 16], CliError> {
    let compact: String = id
        .to_string()
        .chars()
        .filter(|character| *character != '-')
        .collect();
    let bytes = hex::decode(compact).map_err(|_| CliError::Usage)?;
    bytes.try_into().map_err(|_| CliError::Usage)
}

#[expect(
    clippy::future_not_send,
    reason = "this CLI-only contract check is awaited inline with its local runtime adapter"
)]
async fn require_mode_contract<R: PermissionModeRuntime>(
    runtime: &R,
    workspace_id: CanonicalId,
    command_id: CanonicalId,
) -> Result<(), CliError> {
    runtime
        .read_mode_status(workspace_id)
        .await
        .map(|_| ())
        .map_err(|_| CliError::PermissionCommandUnavailable(command_id))
}

#[expect(
    clippy::future_not_send,
    reason = "this CLI-only command readback is awaited inline with its local runtime adapter"
)]
async fn read_mode_command<R: PermissionModeRuntime>(
    runtime: &R,
    workspace_id: CanonicalId,
    command_id: CanonicalId,
) -> Result<PermissionModeCommandStatusV2, CliError> {
    runtime
        .read_mode_command(workspace_id, command_id)
        .await
        .map_err(|error| match error {
            ModeApiError::NotFound => CliError::PermissionCommandUnknown(command_id),
            ModeApiError::Api(_) | ModeApiError::UnknownAfterSend => {
                CliError::PermissionCommandUnavailable(command_id)
            }
        })
}

fn render_validated_mode_status(
    status: PermissionModeCommandStatusV2,
    intent: &PermissionModeSetIntent,
) -> Result<CommandOutput, CliError> {
    if let PermissionModeCommandStatusV2::Committed { receipt } = &status {
        let next_revision = intent.expected_authorization_revision.checked_add(1);
        if receipt.command_id.to_string() != intent.command_id.to_string()
            || receipt.idempotency_key != intent.idempotency_key
            || receipt.authorization_revision != next_revision.unwrap_or(0)
            || receipt.selected_mode != intent.requested_mode
            || receipt.history.selected_mode != intent.requested_mode
            || receipt.history.authorization_revision != receipt.authorization_revision
            || receipt.history.preset_version.as_u16() != intent.preset_version
            || receipt.history.expires_at_unix_ms != intent.expires_at_unix_ms
        {
            return Err(CliError::PermissionCommandUnknown(intent.command_id));
        }
    }
    Ok(render_permission_command_status(status))
}

const fn recovery_cli_error(command_id: CanonicalId, error: RecoveryError) -> CliError {
    match error {
        RecoveryError::Io => CliError::PermissionRecoveryIo(command_id),
        RecoveryError::Corrupt => CliError::PermissionRecoveryCorrupt(command_id),
    }
}

fn canonical_uuid(value: &str) -> Result<(), RecoveryError> {
    let parsed = CanonicalId::parse(value).map_err(|_| RecoveryError::Corrupt)?;
    (parsed.to_string() == value)
        .then_some(())
        .ok_or(RecoveryError::Corrupt)
}

fn canonical_digest(value: &str) -> Result<(), RecoveryError> {
    let decoded = hex::decode(value).map_err(|_| RecoveryError::Corrupt)?;
    (decoded.len() == 32 && hex::encode(decoded) == value)
        .then_some(())
        .ok_or(RecoveryError::Corrupt)
}

fn canonical_session_id(value: &str) -> Result<(), RecoveryError> {
    let decoded = hex::decode(value).map_err(|_| RecoveryError::Corrupt)?;
    (decoded.len() == 16 && hex::encode(decoded) == value)
        .then_some(())
        .ok_or(RecoveryError::Corrupt)
}

fn safe_identity_text(value: &str, maximum: usize) -> Result<(), RecoveryError> {
    (!value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control))
        .then_some(())
        .ok_or(RecoveryError::Corrupt)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "recovery_directory_durability_tests.rs"]
mod recovery_directory_durability_tests;

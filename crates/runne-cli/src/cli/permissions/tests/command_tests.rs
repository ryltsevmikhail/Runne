use super::*;

#[test]
fn parses_read_only_permission_commands_with_canonical_ids() {
    assert!(matches!(
        parse_permissions(args(&["status", "--workspace-id", WORKSPACE])),
        Ok(ParsedPermissionsCommand::Read(PermissionsCommand::Status { workspace_id }))
            if workspace_id.to_string() == WORKSPACE
    ));
    assert!(matches!(
        parse_permissions(args(&[
            "command", "status", "--workspace-id", WORKSPACE, "--command-id", COMMAND
        ])),
        Ok(ParsedPermissionsCommand::Read(PermissionsCommand::CommandStatus { workspace_id, command_id }))
            if workspace_id.to_string() == WORKSPACE && command_id.to_string() == COMMAND
    ));
    assert!(matches!(
        parse_permissions(args(&["approvals", "list"])),
        Ok(ParsedPermissionsCommand::Read(
            PermissionsCommand::ApprovalsList
        ))
    ));
}

#[test]
fn parses_explicit_approval_responses_and_rejects_automatic_confirmation_flags() {
    for (decision, expected) in [
        (
            "approve",
            runne_runtime_client::ApprovalDecisionDto::Approve,
        ),
        ("deny", runne_runtime_client::ApprovalDecisionDto::Deny),
    ] {
        assert!(matches!(
            parse_permissions(args(&[
                "approvals", "respond", "--approval-id", WORKSPACE, "--decision", decision,
                "--command-id", COMMAND, "--idempotency-key", "approval-key-01"
            ])),
            Ok(ParsedPermissionsCommand::ApprovalRespond(intent))
                if intent.approval_id.to_string() == WORKSPACE
                    && intent.command_id.to_string() == COMMAND
                    && intent.idempotency_key == "approval-key-01"
                    && intent.decision == expected
        ));
    }
    assert!(matches!(
        parse_permissions(args(&[
            "approvals",
            "respond",
            "--approval-id",
            WORKSPACE,
            "--decision",
            "approve",
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "approval-key-01",
            "--yes"
        ])),
        Err(CliError::Usage)
    ));
}

#[test]
fn parses_explicit_mode_intent_without_generating_identity() {
    let result = parse_permissions(args(&[
        "mode",
        "set",
        "--workspace-id",
        WORKSPACE,
        "--command-id",
        COMMAND,
        "--idempotency-key",
        "cli-key-01",
        "--mode",
        "full_access",
        "--expected-revision",
        "9",
        "--preset-version",
        "1",
        "--expires-at-unix-ms",
        "none",
    ]));
    assert!(matches!(
        result,
        Ok(ParsedPermissionsCommand::ModeSet(intent))
            if intent.workspace_id.to_string() == WORKSPACE
                && intent.command_id.to_string() == COMMAND
                && intent.idempotency_key == "cli-key-01"
                && intent.requested_mode == runne_runtime_client::PermissionModeV1::FullAccess
                && intent.expected_authorization_revision == 9
                && intent.preset_version == 1
                && intent.expires_at_unix_ms.is_none()
    ));
}

#[test]
fn parser_rejects_ambiguous_or_unimplemented_commands() {
    let cases: &[&[&str]] = &[
        &["status"],
        &["status", "--workspace-id", "not-an-id"],
        &["status", "--workspace-id", WORKSPACE, "extra"],
        &["command", "status", "--workspace-id", WORKSPACE],
        &["approvals", "list", "extra"],
        &["mode", "set", "--workspace-id", WORKSPACE],
        &[
            "mode",
            "set",
            "--workspace-id",
            WORKSPACE,
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "cli-key-01",
            "--mode",
            "risk_based",
            "--expected-revision",
            "9",
            "--preset-version",
            "2",
            "--expires-at-unix-ms",
            "none",
        ],
        &[
            "mode",
            "set",
            "--workspace-id",
            WORKSPACE,
            "--command-id",
            COMMAND,
            "--idempotency-key",
            "cli-key-01",
            "--mode",
            "ask_always",
            "--expected-revision",
            "9",
            "--preset-version",
            "1",
            "--expires-at-unix-ms",
            "0",
        ],
        &[
            "status",
            "--workspace-id",
            "5d3a7c8e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
        ],
    ];
    for values in cases {
        assert!(
            matches!(parse_permissions(args(values)), Err(CliError::Usage)),
            "{values:?}"
        );
    }
}
#[test]
fn help_path_routes_only_commands_currently_implemented() {
    assert_eq!(help_for(&["permissions"]), PERMISSIONS_HELP);
    assert_eq!(
        help_for(&["permissions", "status"]),
        PERMISSIONS_STATUS_HELP
    );
    assert_eq!(
        help_for(&["permissions", "command", "status"]),
        PERMISSIONS_COMMAND_STATUS_HELP
    );
    assert_eq!(
        help_for(&["permissions", "approvals", "list"]),
        PERMISSIONS_APPROVALS_LIST_HELP
    );
    assert_eq!(
        help_for(&["permissions", "mode", "set"]),
        PERMISSIONS_MODE_SET_HELP
    );
}
#[test]
fn help_argument_is_closed_before_any_runtime_connection() {
    assert!(matches!(
        parse_permissions(args(&["--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_HELP
    ));
    assert!(matches!(
        parse_permissions(args(&["status", "--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_STATUS_HELP
    ));
    assert!(matches!(
        parse_permissions(args(&["mode", "set", "--help"])),
        Err(CliError::Help(text)) if text == PERMISSIONS_MODE_SET_HELP
    ));
}

#[test]
fn unknown_command_outcome_has_a_distinct_machine_exit_code() {
    assert_eq!(ErrorCode::CommandOutcomeUnknown.exit_code(), 5);
}

#[test]
fn permission_mode_human_labels_match_the_trusted_native_warning() {
    use runne_runtime_client::PermissionModeV1 as Mode;
    let cases = [
        (Mode::AskAlways, "Запрашивать разрешение"),
        (Mode::RiskBased, "Подтверждать за меня"),
        (Mode::FullAccess, "Полный доступ"),
    ];
    for (mode, expected) in cases {
        assert_eq!(permission_mode_label(mode), expected);
    }
}

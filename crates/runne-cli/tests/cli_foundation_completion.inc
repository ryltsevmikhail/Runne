#[test]
fn completion_help_flag_shows_completion_help() {
    let output = run_cli(&["completion", "--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Generate shell completion scripts"));
}

#[test]
fn help_completion_shows_completion_help() {
    let output = run_cli(&["help", "completion"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Generate shell completion scripts"));
}

#[test]
fn top_level_help_includes_completion() {
    let output = run_cli(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("completion"));
    assert!(stdout.contains("Generate shell completion scripts"));
}

#[test]
fn authority_and_release_are_exposed_by_root_help_and_help_for() {
    let root_help = run_cli(&["--help"]);
    let root_help = String::from_utf8_lossy(&root_help.stdout);
    assert!(root_help.contains("authority"));
    assert!(root_help.contains("release"));

    for command in ["authority", "release"] {
        let output = run_cli(&["help", command]);
        assert!(output.status.success(), "{command}");
        assert!(String::from_utf8_lossy(&output.stdout).contains(command));
    }
}

#[test]
fn completion_bash_generates_script() {
    let output = run_cli(&["completion", "bash"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_runne"));
    assert!(stdout.contains("complete -F"));
}

#[test]
fn completion_zsh_generates_script() {
    let output = run_cli(&["completion", "zsh"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("_runne"));
    assert!(stdout.contains("compdef"));
}

#[test]
fn completion_fish_generates_script() {
    let output = run_cli(&["completion", "fish"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("complete -c runne"));
}

#[test]
fn completion_powershell_generates_script() {
    let output = run_cli(&["completion", "powershell"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Register-ArgumentCompleter"));
}

#[test]
fn completion_invalid_shell_returns_error() {
    let output = run_cli(&["completion", "invalid"]);
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn all_completion_scripts_expose_authority_and_release() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = run_cli(&["completion", shell]);
        assert!(output.status.success(), "{shell}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("authority"), "{shell}");
        assert!(stdout.contains("release"), "{shell}");
    }
}

#[test]
fn malformed_global_format_stops_all_top_level_dispatch() {
    let commands = ["--version", "authority", "release"];
    let forms = [
        ("invalid", ["--format", "yaml"]),
        ("missing", ["--format", ""]),
        ("duplicate", ["--format=text", "--format=json"]),
    ];

    for command in commands {
        for (kind, form) in forms {
            let mut arguments = vec![command];
            arguments.extend(form.iter().filter(|argument| !argument.is_empty()));
            let output = run_cli(&arguments);
            assert_eq!(output.status.code(), Some(2), "{kind}: {arguments:?}");
            assert!(output.stdout.is_empty(), "{kind}: {arguments:?}");
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("Runne command-line interface"));
        }
    }
}

#[test]
fn valid_global_format_after_command_remains_supported() {
    for arguments in [
        &["--version", "--format", "text"][..],
        &["--version", "--format=json"][..],
    ] {
        let output = run_cli(arguments);
        assert!(output.status.success(), "{arguments:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("runne"));
    }
}

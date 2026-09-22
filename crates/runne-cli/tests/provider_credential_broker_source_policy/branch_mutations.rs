use super::{BROKER_SOURCE, broker_branch_violations, replace_first, replace_once};

type Mutation = (&'static str, String);

fn assert_no_accepted_mutation(cases: &[Mutation]) {
    let accepted: Vec<_> = cases
        .iter()
        .filter_map(|(label, source)| {
            broker_branch_violations(source)
                .is_empty()
                .then_some(*label)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}

#[test]
fn broker_branch_policy_rejects_platform_and_ingress_mutations() {
    let cases = [
        (
            "Unix-wide receive",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(target_os = \"macos\")]\n    {",
                "#[cfg(unix)]\n    {",
            ),
        ),
        (
            "Unix-wide linux branch",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(target_os = \"linux\")]\n    {\n        // Validate the pipe shape",
                "#[cfg(unix)]\n    {\n        // Validate the pipe shape",
            ),
        ),
        (
            "not-any fallthrough widened",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(not(any(target_os = \"macos\", target_os = \"linux\")))]",
                "#[cfg(not(target_os = \"macos\"))]",
            ),
        ),
        (
            "discarded secret slot",
            replace_once(
                BROKER_SOURCE,
                "let secret = channel::InheritedSecretInputSlot::inspect()\n            .inspect_err",
                "let _ = channel::InheritedSecretInputSlot::inspect()\n            .inspect_err",
            ),
        ),
        (
            "discarded handoff",
            replace_once(BROKER_SOURCE, "let handoff =", "let _ ="),
        ),
        (
            "wrong ingress error",
            replace_first(
                BROKER_SOURCE,
                "CliError::CredentialOperation",
                "CliError::UnsupportedCredentialBackend",
            ),
        ),
        (
            "wrong pinned observation error",
            replace_once(
                BROKER_SOURCE,
                ".observe_current_pinned_writer_session()\n            .inspect_err(|_| writer_stage::session_observe_failed())\n            .map_err(|_| CliError::CredentialOperation)?;",
                ".observe_current_pinned_writer_session()\n            .inspect_err(|_| writer_stage::session_observe_failed())\n            .map_err(|_| CliError::UnsupportedCredentialBackend)?;",
            ),
        ),
        (
            "missing argv end gate",
            replace_once(BROKER_SOURCE, "expect_end(&arguments)?;", ""),
        ),
        (
            "cfg-hidden argv end gate",
            replace_once(
                BROKER_SOURCE,
                "expect_end(&arguments)?;",
                "#[cfg(any())]\n    expect_end(&arguments)?;",
            ),
        ),
        (
            "cfg-hidden handoff",
            replace_once(
                BROKER_SOURCE,
                "let handoff =",
                "#[cfg(any())]\n        let handoff =",
            ),
        ),
        (
            "linux branch stdin read",
            replace_once(
                BROKER_SOURCE,
                "descriptors before authenticating or claiming.\n        let secret",
                "descriptors before authenticating or claiming.\n        let _ = std::io::stdin();\n        let secret",
            ),
        ),
        (
            "alternate runner",
            replace_once(
                BROKER_SOURCE,
                "run::run_authenticated_writer(pinned, secret)",
                "run::execute_claimed_writer(pinned, secret)",
            ),
        ),
        (
            "wrong post-handoff result",
            replace_first(
                BROKER_SOURCE,
                "Err(CliError::UnsupportedCredentialBackend)",
                "Err(CliError::CredentialOperation)",
            ),
        ),
    ];
    assert_no_accepted_mutation(&cases);
}

#[test]
fn broker_branch_policy_rejects_stage_diagnostics_mutations() {
    let cases = [
        (
            "missing stage marker",
            replace_once(
                BROKER_SOURCE,
                "writer_stage::secret_inspect();\n        let secret",
                "let secret",
            ),
        ),
        (
            "unaudited stage marker",
            replace_once(
                BROKER_SOURCE,
                "writer_stage::secret_inspect();",
                "writer_stage::endpoint_receive();",
            ),
        ),
        (
            "missing failed stage marker",
            replace_once(
                BROKER_SOURCE,
                "            .inspect_err(|_| writer_stage::secret_inspect_failed())\n",
                "",
            ),
        ),
        (
            "unaudited failed stage marker",
            replace_once(
                BROKER_SOURCE,
                "writer_stage::secret_inspect_failed()",
                "writer_stage::secret_inspect()",
            ),
        ),
        (
            "stage marker with argument",
            replace_once(
                BROKER_SOURCE,
                "writer_stage::secret_inspect();",
                "writer_stage::secret_inspect(secret);",
            ),
        ),
        (
            "extra stage-block statement",
            replace_once(
                BROKER_SOURCE,
                "writer_stage::authenticated_run();\n        run::",
                "writer_stage::authenticated_run();\n        let _ = 0;\n        run::",
            ),
        ),
        (
            "runner failure discards stage reporting",
            replace_once(
                BROKER_SOURCE,
                ".inspect_err(|_| writer_stage::authenticated_run_failed())",
                "",
            ),
        ),
    ];
    assert_no_accepted_mutation(&cases);
}

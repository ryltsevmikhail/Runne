use super::{BROKER_SOURCE, broker_branch_violations, replace_first, replace_once};

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
            "Linux-only fallback",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(not(target_os = \"macos\"))]",
                "#[cfg(target_os = \"linux\")]",
            ),
        ),
        (
            "discarded secret slot",
            replace_once(BROKER_SOURCE, "let secret =", "let _ ="),
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
                ".observe_current_pinned_writer_session()\n            .map_err(|_| CliError::CredentialOperation)?;",
                ".observe_current_pinned_writer_session()\n            .map_err(|_| CliError::UnsupportedCredentialBackend)?;",
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
            "non-macOS stdin read",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(not(target_os = \"macos\"))]\n    {",
                "#[cfg(not(target_os = \"macos\"))]\n    {\n        let _ = std::io::stdin();",
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
    let accepted: Vec<_> = cases
        .into_iter()
        .filter_map(|(label, source)| {
            broker_branch_violations(&source)
                .is_empty()
                .then_some(label)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}

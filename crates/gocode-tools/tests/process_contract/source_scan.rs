use source_lexer::{module_child_paths, scan_rust_source};
use source_manifest::{
    assert_sorted_unique, assert_sources_exclude, source_violations, PROCESS_CONTRACT_SOURCES,
    TASK6_TEST_FIXTURE_SOURCES,
};

#[test]
fn lexer_detects_forbidden_api_after_url_literal() {
    let forbidden = [["std::pro", "cess"].concat(), ["Com", "mand::new"].concat()].concat();
    let source = format!("let url = \"https://example.invalid/a//b\"; {forbidden}();");

    let scanned = scan_rust_source(&source).expect("valid source");

    assert!(scanned.normalized_code.contains(&forbidden));
}

#[test]
fn lexer_ignores_line_and_nested_block_comments() {
    let forbidden = ["std::pro", "cess"].concat();
    let source = format!("// {forbidden}\n/* outer /* {forbidden} */ outer */\nlet allowed = 1;");

    let scanned = scan_rust_source(&source).expect("valid source");

    assert!(!scanned.code.contains(&forbidden));
    assert!(!scanned.normalized_code.contains(&forbidden));
}

#[test]
fn lexer_ignores_api_text_in_ordinary_raw_byte_and_c_literals() {
    let forbidden = ["std::pro", "cess"].concat();
    let source = format!(
        "let ordinary = \"{forbidden}\"; let raw = r###\"{forbidden}\"###; let bytes = b\"{forbidden}\"; let c = c\"{forbidden}\";"
    );

    let scanned = scan_rust_source(&source).expect("valid source");

    assert!(!scanned.code.contains(&forbidden));
    assert!(!scanned.normalized_code.contains(&forbidden));
    assert_eq!(scanned.string_literals.len(), 4);
}

#[test]
fn lexer_exposes_forbidden_shell_literal_in_literal_channel() {
    let shell = [["s", "h"].concat(), [" -", "c"].concat()].concat();
    let source = format!("let command = \"{shell}\";");

    let scanned = scan_rust_source(&source).expect("valid source");

    assert!(scanned
        .string_literals
        .iter()
        .any(|literal| literal == &shell));
}

#[test]
fn lexer_normalizes_escaped_command_literal() {
    let shell = [["s", "h"].concat(), [" -", "c"].concat()].concat();
    let source = "let command = \"sh\\x20-c\";";

    let violations = source_violations(&[("fixture", source)], &[], &[shell]);

    assert_eq!(violations, ["fixture: literal sh -c"]);
}

#[test]
fn lexer_normalizes_paths_split_by_comments_and_whitespace() {
    let forbidden = ["std::pro", "cess"].concat();
    let source = format!(
        "{prefix} /* x */ :: process::Command::new(\"safe\");",
        prefix = "std"
    );

    let scanned = scan_rust_source(&source).expect("valid source");

    assert!(scanned.normalized_code.contains(&forbidden));
}

#[test]
fn lexer_fails_closed_for_unfinished_literals_and_comments() {
    for source in [
        "let value = \"unfinished",
        "let value = r#\"unfinished\"",
        "/* unfinished",
    ] {
        assert!(scan_rust_source(source).is_err(), "must reject: {source}");
    }
}

#[test]
fn scanner_negative_fixtures_detect_every_forbidden_family() {
    let code = forbidden_code();
    let literals = forbidden_literals();
    let fixtures = code
        .iter()
        .map(|token| ("code", format!("fn fixture() {{ {token}; }}")))
        .chain(
            literals
                .iter()
                .map(|token| ("literal", format!("let route = \"{token}\";"))),
        )
        .collect::<Vec<_>>();
    let sources = fixtures
        .iter()
        .map(|(path, source)| (*path, source.as_str()))
        .collect::<Vec<_>>();
    let violations = source_violations(&sources, &code, &literals);

    for token in code.iter().chain(literals.iter()) {
        assert!(
            violations
                .iter()
                .any(|violation| violation.ends_with(token)),
            "negative fixture was not found: {token}"
        );
    }
}

#[test]
fn process_contract_production_paths_have_no_ambient_or_process_apis() {
    assert_sources_exclude(
        &PROCESS_CONTRACT_SOURCES,
        &forbidden_code(),
        &forbidden_literals(),
    );
}

#[test]
fn task6_test_fixtures_have_no_real_process_or_ambient_apis() {
    let test_fixture_sources = TASK6_TEST_FIXTURE_SOURCES
        .iter()
        .filter(|(path, _)| {
            !matches!(
                *path,
                "crates/gocode-tools/tests/process_contract/source_scan.rs"
                    | "crates/gocode-tools/tests/process_contract/source_scan_alias.rs"
            )
        })
        .copied()
        .collect::<Vec<_>>();
    assert_sources_exclude(
        &test_fixture_sources,
        &forbidden_code(),
        &forbidden_literals(),
    );
}

#[test]
fn source_manifest_is_complete_and_facades_use_standard_modules() {
    assert_sorted_unique(&PROCESS_CONTRACT_SOURCES, "production");
    for (path, source) in PROCESS_CONTRACT_SOURCES {
        assert!(
            [
                "crates/gocode-security/src/process_contract",
                "crates/platform-ports/src/process",
                "crates/gocode-tools/src/process_contract",
                "crates/gocode-platform/src/process_contract",
            ]
            .iter()
            .any(|root| path == format!("{root}.rs") || path.starts_with(&format!("{root}/"))),
            "unexpected production root: {path}"
        );
        for forbidden_path in ["/tests/", "/docs/", "/broker/process", "/containment/"] {
            assert!(
                !path.contains(forbidden_path),
                "legacy or non-production path: {path}"
            );
        }
        assert!(
            path == "crates/platform-ports/src/process.rs" || !path.ends_with("/src/process.rs"),
            "legacy process facade: {path}"
        );
        let scanned = scan_source(source);
        assert!(
            !scanned.normalized_code.contains("#[path"),
            "nonstandard module path: {path}"
        );
        assert!(
            !scanned.normalized_code.contains("include!"),
            "included module source: {path}"
        );
        for expected_path in module_child_paths(path, &scanned.code)
            .unwrap_or_else(|error| panic!("invalid module declaration: {path}: {error:?}"))
        {
            assert!(
                PROCESS_CONTRACT_SOURCES
                    .iter()
                    .any(|(path, _)| *path == expected_path),
                "missing source manifest: {expected_path}"
            );
        }
    }
}

#[test]
fn task6_test_fixture_manifest_is_sorted_unique_and_includes_the_source_scanner() {
    assert_sorted_unique(&TASK6_TEST_FIXTURE_SOURCES, "test fixture");
    assert!(TASK6_TEST_FIXTURE_SOURCES
        .iter()
        .any(|(path, _)| path.ends_with("/source_scan.rs")));
}

fn scan_source(source: &str) -> source_lexer::ScannedRustSource {
    scan_rust_source(source).unwrap_or_else(|error| panic!("invalid Rust source: {error:?}"))
}

fn forbidden_code() -> Vec<String> {
    [
        ["std::pro", "cess"].concat(),
        ["tokio::pro", "cess"].concat(),
        ["async_pro", "cess"].concat(),
        ["Com", "mand::new"].concat(),
        ["libc::", "fork"].concat(),
        ["libc::", "vfork"].concat(),
        ["libc::", "exec"].concat(),
        ["libc::", "posix_spawn"].concat(),
        ["libc::", "kill"].concat(),
        ["libc::", "raise"].concat(),
        ["libc::", "signal"].concat(),
        ["nix::unistd::", "fork"].concat(),
        ["nix::unistd::", "exec"].concat(),
        ["nix::sys::", "signal"].concat(),
        ["windows_sys::Win32::System::Threading::", "CreateProcess"].concat(),
        ["std::", "fs"].concat(),
        ["tokio::", "fs"].concat(),
        ["std::", "env"].concat(),
        ["current_", "exe"].concat(),
        ["current_", "dir"].concat(),
        ["std::", "net"].concat(),
        ["tokio::", "net"].concat(),
        ["tauri", "::"].concat(),
        ["tauri_plugin_", "shell"].concat(),
        ["wry", "::"].concat(),
        ["un", "safe"].concat(),
        ["ex", "tern"].concat(),
    ]
    .into()
}

fn forbidden_literals() -> Vec<String> {
    [
        ["/bin/", "sh"].concat(),
        [["s", "h"].concat(), [" -", "c"].concat()].concat(),
        [["ba", "sh"].concat(), [" -", "c"].concat()].concat(),
        [["cmd", ".exe"].concat(), [" /", "C"].concat()].concat(),
        ["power", "shell"].concat(),
        ["pw", "sh"].concat(),
        ["@tauri-apps/plugin-", "shell"].concat(),
        ["child_", "process"].concat(),
        ["Deno.", "Command"].concat(),
        ["Bun.", "spawn"].concat(),
        ["doc", "ker"].concat(),
        ["pod", "man"].concat(),
        ["container", "d"].concat(),
        [["kube", "ctl"].concat(), [" ex", "ec"].concat()].concat(),
    ]
    .into()
}

#[test]
fn counter_proof_meta_tests_keep_virtual_calls_and_stubs_fail_closed() {
    let source = |path| {
        TASK6_TEST_FIXTURE_SOURCES
            .iter()
            .find(|(candidate, _)| *candidate == path)
            .unwrap()
            .1
    };
    let denied = source("crates/gocode-tools/src/process_contract/orchestrator_tests.rs");
    let cancelled =
        source("crates/gocode-tools/src/process_contract/orchestrator_lifecycle_tests.rs");
    let replay = source("crates/gocode-tools/src/process_contract/orchestrator_failure_tests.rs");
    let stubs = source("crates/gocode-platform/tests/process_contract_stubs.rs");

    assert!(denied.contains("timeout_before_dispatch_does_not_claim_or_touch_the_virtual_platform"));
    assert!(
        cancelled.contains("cancellation_before_dispatch_is_denied_without_claim_or_platform_call")
    );
    assert!(denied.contains("call_log") && denied.contains("is_empty"));
    assert!(cancelled.contains("call_log") && cancelled.contains("is_empty"));
    assert!(replay.contains("launch_and_forced_ambiguities_are_uncertain_while_graceful_cleanup_is_terminal") && replay.contains("let calls"));
    assert!(replay.contains("call_log().expect(\"healthy fixture\"), calls"));
    assert!(
        stubs.contains("NotQualified")
            && stubs.contains("Unsupported")
            && stubs.contains("port.launch")
    );
}

use super::{source_lexer::scan_rust_source, source_lexer_concat::concat_literals};

#[rustfmt::skip]
pub(super) const LEGACY_TEST_SOURCES: [(&str, &str); 3] = [
    ("crates/gocode-security/src/broker/process/tests.rs", include_str!("../../../gocode-security/src/broker/process/tests.rs")),
    ("crates/gocode-security/tests/process_containment_admission.rs", include_str!("../../../gocode-security/tests/process_containment_admission.rs")),
    ("crates/gocode-tools/tests/process_executor.rs", include_str!("../process_executor.rs")),
];

#[rustfmt::skip]
pub(super) const PROCESS_CONTRACT_SOURCES: [(&str, &str); 35] = [
    ("crates/gocode-platform/src/process_contract.rs", include_str!("../../../gocode-platform/src/process_contract.rs")),
    ("crates/gocode-platform/src/process_contract/linux.rs", include_str!("../../../gocode-platform/src/process_contract/linux.rs")),
    ("crates/gocode-platform/src/process_contract/macos.rs", include_str!("../../../gocode-platform/src/process_contract/macos.rs")),
    ("crates/gocode-platform/src/process_contract/selector.rs", include_str!("../../../gocode-platform/src/process_contract/selector.rs")),
    ("crates/gocode-platform/src/process_contract/status.rs", include_str!("../../../gocode-platform/src/process_contract/status.rs")),
    ("crates/gocode-platform/src/process_contract/windows.rs", include_str!("../../../gocode-platform/src/process_contract/windows.rs")),
    ("crates/gocode-security/src/process_contract.rs", include_str!("../../../gocode-security/src/process_contract.rs")),
    ("crates/gocode-security/src/process_contract/authorization.rs", include_str!("../../../gocode-security/src/process_contract/authorization.rs")),
    ("crates/gocode-security/src/process_contract/context.rs", include_str!("../../../gocode-security/src/process_contract/context.rs")),
    ("crates/gocode-security/src/process_contract/digest.rs", include_str!("../../../gocode-security/src/process_contract/digest.rs")),
    ("crates/gocode-security/src/process_contract/error.rs", include_str!("../../../gocode-security/src/process_contract/error.rs")),
    ("crates/gocode-security/src/process_contract/ids.rs", include_str!("../../../gocode-security/src/process_contract/ids.rs")),
    ("crates/gocode-security/src/process_contract/intent.rs", include_str!("../../../gocode-security/src/process_contract/intent.rs")),
    ("crates/gocode-security/src/process_contract/intent/input.rs", include_str!("../../../gocode-security/src/process_contract/intent/input.rs")),
    ("crates/gocode-tools/src/process_contract.rs", include_str!("../../src/process_contract.rs")),
    ("crates/gocode-tools/src/process_contract/claim.rs", include_str!("../../src/process_contract/claim.rs")),
    ("crates/gocode-tools/src/process_contract/control.rs", include_str!("../../src/process_contract/control.rs")),
    ("crates/gocode-tools/src/process_contract/error.rs", include_str!("../../src/process_contract/error.rs")),
    ("crates/gocode-tools/src/process_contract/evidence.rs", include_str!("../../src/process_contract/evidence.rs")),
    ("crates/gocode-tools/src/process_contract/journal.rs", include_str!("../../src/process_contract/journal.rs")),
    ("crates/gocode-tools/src/process_contract/lifecycle.rs", include_str!("../../src/process_contract/lifecycle.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator.rs", include_str!("../../src/process_contract/orchestrator.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_input.rs", include_str!("../../src/process_contract/orchestrator_input.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_settlement.rs", include_str!("../../src/process_contract/orchestrator_settlement.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_supervision.rs", include_str!("../../src/process_contract/orchestrator_supervision.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_termination.rs", include_str!("../../src/process_contract/orchestrator_termination.rs")),
    ("crates/gocode-tools/src/process_contract/output.rs", include_str!("../../src/process_contract/output.rs")),
    ("crates/gocode-tools/src/process_contract/output/output_collector.rs", include_str!("../../src/process_contract/output/output_collector.rs")),
    ("crates/gocode-tools/src/process_contract/output/output_payload.rs", include_str!("../../src/process_contract/output/output_payload.rs")),
    ("crates/gocode-tools/src/process_contract/output/output_types.rs", include_str!("../../src/process_contract/output/output_types.rs")),
    ("crates/gocode-tools/src/process_contract/settlement.rs", include_str!("../../src/process_contract/settlement.rs")),
    ("crates/platform-ports/src/process.rs", include_str!("../../../platform-ports/src/process.rs")),
    ("crates/platform-ports/src/process/port.rs", include_str!("../../../platform-ports/src/process/port.rs")),
    ("crates/platform-ports/src/process/request.rs", include_str!("../../../platform-ports/src/process/request.rs")),
    ("crates/platform-ports/src/process/types.rs", include_str!("../../../platform-ports/src/process/types.rs")),
];

#[rustfmt::skip]
pub(super) const TASK6_TEST_FIXTURE_SOURCES: [(&str, &str); 46] = [
    ("crates/gocode-platform/src/process_contract/tests.rs", include_str!("../../../gocode-platform/src/process_contract/tests.rs")),
    ("crates/gocode-platform/tests/process_contract_stubs.rs", include_str!("../../../gocode-platform/tests/process_contract_stubs.rs")),
    ("crates/gocode-security/src/process_contract/tests.rs", include_str!("../../../gocode-security/src/process_contract/tests.rs")),
    ("crates/gocode-security/src/process_contract/tests/approval.rs", include_str!("../../../gocode-security/src/process_contract/tests/approval.rs")),
    ("crates/gocode-security/src/process_contract/tests/authorization.rs", include_str!("../../../gocode-security/src/process_contract/tests/authorization.rs")),
    ("crates/gocode-security/src/process_contract/tests/authorization/basic.rs", include_str!("../../../gocode-security/src/process_contract/tests/authorization/basic.rs")),
    ("crates/gocode-security/src/process_contract/tests/authorization/replay.rs", include_str!("../../../gocode-security/src/process_contract/tests/authorization/replay.rs")),
    ("crates/gocode-security/src/process_contract/tests/current_context.rs", include_str!("../../../gocode-security/src/process_contract/tests/current_context.rs")),
    ("crates/gocode-security/src/process_contract/tests/current_context/verification.rs", include_str!("../../../gocode-security/src/process_contract/tests/current_context/verification.rs")),
    ("crates/gocode-security/src/process_contract/tests/digest.rs", include_str!("../../../gocode-security/src/process_contract/tests/digest.rs")),
    ("crates/gocode-security/src/process_contract/tests/environment.rs", include_str!("../../../gocode-security/src/process_contract/tests/environment.rs")),
    ("crates/gocode-security/src/process_contract/tests/input.rs", include_str!("../../../gocode-security/src/process_contract/tests/input.rs")),
    ("crates/gocode-security/src/process_contract/tests/redaction.rs", include_str!("../../../gocode-security/src/process_contract/tests/redaction.rs")),
    ("crates/gocode-security/src/process_contract/tests/support.rs", include_str!("../../../gocode-security/src/process_contract/tests/support.rs")),
    ("crates/gocode-security/tests/process_contract.rs", include_str!("../../../gocode-security/tests/process_contract.rs")),
    ("crates/gocode-security/tests/process_contract/authorization.rs", include_str!("../../../gocode-security/tests/process_contract/authorization.rs")),
    ("crates/gocode-security/tests/process_contract/bounds.rs", include_str!("../../../gocode-security/tests/process_contract/bounds.rs")),
    ("crates/gocode-security/tests/process_contract/intent.rs", include_str!("../../../gocode-security/tests/process_contract/intent.rs")),
    ("crates/gocode-security/tests/process_contract/support.rs", include_str!("../../../gocode-security/tests/process_contract/support.rs")),
    ("crates/gocode-tools/src/process_contract/claim_unit_tests.rs", include_str!("../../src/process_contract/claim_unit_tests.rs")),
    ("crates/gocode-tools/src/process_contract/f1_replay_tests.rs", include_str!("../../src/process_contract/f1_replay_tests.rs")),
    ("crates/gocode-tools/src/process_contract/f1_tests.rs", include_str!("../../src/process_contract/f1_tests.rs")),
    ("crates/gocode-tools/src/process_contract/fixture.rs", include_str!("../../src/process_contract/fixture.rs")),
    ("crates/gocode-tools/src/process_contract/fixture_ports.rs", include_str!("../../src/process_contract/fixture_ports.rs")),
    ("crates/gocode-tools/src/process_contract/fixture_tests.rs", include_str!("../../src/process_contract/fixture_tests.rs")),
    ("crates/gocode-tools/src/process_contract/lifecycle_unit_tests.rs", include_str!("../../src/process_contract/lifecycle_unit_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_failure_tests.rs", include_str!("../../src/process_contract/orchestrator_failure_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_lifecycle_tests.rs", include_str!("../../src/process_contract/orchestrator_lifecycle_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_marker_tests.rs", include_str!("../../src/process_contract/orchestrator_marker_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_output_tests.rs", include_str!("../../src/process_contract/orchestrator_output_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_supervision_completion_tests.rs", include_str!("../../src/process_contract/orchestrator_supervision_completion_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_supervision_tests.rs", include_str!("../../src/process_contract/orchestrator_supervision_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_termination_tests.rs", include_str!("../../src/process_contract/orchestrator_termination_tests.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_test_support.rs", include_str!("../../src/process_contract/orchestrator_test_support.rs")),
    ("crates/gocode-tools/src/process_contract/orchestrator_tests.rs", include_str!("../../src/process_contract/orchestrator_tests.rs")),
    ("crates/gocode-tools/src/process_contract/output/tests.rs", include_str!("../../src/process_contract/output/tests.rs")),
    ("crates/gocode-tools/src/process_contract/output/tests/truncation.rs", include_str!("../../src/process_contract/output/tests/truncation.rs")),
    ("crates/gocode-tools/src/process_contract/recovery_tests.rs", include_str!("../../src/process_contract/recovery_tests.rs")),
    ("crates/gocode-tools/src/process_contract/settlement_unit_tests.rs", include_str!("../../src/process_contract/settlement_unit_tests.rs")),
    ("crates/gocode-tools/tests/process_contract.rs", include_str!("../process_contract.rs")),
    ("crates/gocode-tools/tests/process_contract/control.rs", include_str!("control.rs")),
    ("crates/gocode-tools/tests/process_contract/output.rs", include_str!("output.rs")),
    ("crates/gocode-tools/tests/process_contract/public_api.rs", include_str!("public_api.rs")),
    ("crates/gocode-tools/tests/process_contract/source_scan.rs", include_str!("source_scan.rs")),
    ("crates/gocode-tools/tests/process_contract/source_scan_alias.rs", include_str!("source_scan_alias.rs")),
    ("crates/platform-ports/src/process/tests.rs", include_str!("../../../platform-ports/src/process/tests.rs")),
];

#[rustfmt::skip]
pub(super) const TASK6_INTEGRATION_SURFACES: [(&str, &str); 8] = [
    ("crates/gocode-platform/Cargo.toml", include_str!("../../../gocode-platform/Cargo.toml")),
    ("crates/gocode-platform/src/lib.rs", include_str!("../../../gocode-platform/src/lib.rs")),
    ("crates/gocode-security/Cargo.toml", include_str!("../../../gocode-security/Cargo.toml")),
    ("crates/gocode-security/src/lib.rs", include_str!("../../../gocode-security/src/lib.rs")),
    ("crates/gocode-tools/Cargo.toml", include_str!("../../Cargo.toml")),
    ("crates/gocode-tools/src/lib.rs", include_str!("../../src/lib.rs")),
    ("crates/platform-ports/Cargo.toml", include_str!("../../../platform-ports/Cargo.toml")),
    ("crates/platform-ports/src/lib.rs", include_str!("../../../platform-ports/src/lib.rs")),
];

pub(super) fn assert_sources_exclude(
    sources: &[(&str, &str)],
    code_tokens: &[String],
    literal_tokens: &[String],
) {
    let violations = source_violations(sources, code_tokens, literal_tokens);
    assert!(
        violations.is_empty(),
        "forbidden contract APIs:\n{}",
        violations.join("\n")
    );
}

pub(super) fn assert_sorted_unique(sources: &[(&str, &str)], kind: &str) {
    let paths = sources.iter().map(|(path, _)| *path).collect::<Vec<_>>();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(paths, sorted, "{kind} manifest must be sorted and unique");
}

pub(super) fn source_violations(
    sources: &[(&str, &str)],
    code_tokens: &[String],
    literal_tokens: &[String],
) -> Vec<String> {
    let mut violations = Vec::new();
    for (path, source) in sources {
        let scanned = scan_rust_source(source)
            .unwrap_or_else(|error| panic!("invalid Rust source: {path}: {error:?}"));
        let canonical_code = scanned.normalized_code.replace(['{', '}'], "");
        for token in code_tokens
            .iter()
            .filter(|token| canonical_code.contains(*token))
        {
            violations.push(format!("{path}: {token}"));
        }
        let literals = scanned
            .string_literals
            .iter()
            .filter_map(|literal| normalize_literal(literal))
            .chain(concat_literals(source))
            .collect::<Vec<_>>();
        for token in literal_tokens.iter().filter(|token| {
            literals.iter().any(|literal| {
                literal.contains(*token) && !(literal.ends_with("PATH") && *token == "PATH")
            })
        }) {
            violations.push(format!("{path}: literal {token}"));
        }
    }
    violations
}

fn normalize_literal(literal: &str) -> Option<String> {
    let mut normalized = String::new();
    let mut characters = literal.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            normalized.push(character);
            continue;
        }
        match characters.next()? {
            '\\' => normalized.push('\\'),
            '"' => normalized.push('"'),
            'n' => normalized.push('\n'),
            'r' => normalized.push('\r'),
            't' => normalized.push('\t'),
            '0' => normalized.push('\0'),
            'x' => {
                let digits = [characters.next()?, characters.next()?];
                let value = u8::from_str_radix(&digits.iter().collect::<String>(), 16).ok()?;
                normalized.push(char::from(value));
            }
            'u' => {
                (characters.next()? == '{').then_some(())?;
                let digits = characters
                    .by_ref()
                    .take_while(|value| *value != '}')
                    .collect::<String>();
                let value = u32::from_str_radix(&digits, 16).ok()?;
                normalized.push(char::from_u32(value)?);
            }
            _ => return None,
        }
    }
    Some(normalized)
}

#[test]
fn source_scan_rejects_ambient_executable_and_cwd_helpers() {
    let helpers = [["current_", "exe"], ["current_", "dir"]]
        .into_iter()
        .map(|parts| parts.concat())
        .collect::<Vec<_>>();
    let violations = LEGACY_TEST_SOURCES
        .into_iter()
        .flat_map(|(path, source)| {
            helpers
                .iter()
                .filter(move |helper| source_contains_helper(source, helper))
                .map(move |helper| format!("{path}: {helper}"))
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "environment-derived legacy test helpers are forbidden:\n{}",
        violations.join("\n")
    );
}

#[test]
fn public_facade_does_not_reexport_claim_mutation_authority() {
    let facade = include_str!("../../src/lib.rs");
    for hidden in [
        "ProcessClaimBindingV1",
        "ProcessClaimInputV1",
        "ProcessClaimOutcomeV1",
        "VirtualProcessTreeFixtureV1",
    ] {
        assert!(!facade.contains(hidden), "public mutation export: {hidden}");
    }
}

#[test]
fn separate_writable_terminal_store_absent() {
    let sources = [
        include_str!("../../src/process_contract.rs"),
        include_str!("../../src/lib.rs"),
    ];
    let evidence = include_str!("../../src/process_contract/evidence.rs");
    for removed in ["ProcessTerminalEvidenceStoreV1", "ProcessAuditTrailV1"] {
        assert!(
            sources.iter().all(|source| !source.contains(removed)),
            "public export: {removed}"
        );
        assert!(
            !evidence.contains(&format!("pub struct {removed}")),
            "writable source: {removed}"
        );
    }
}

#[test]
fn whole_slice_capture_api_absent() {
    assert!(!include_str!("../../src/process_contract/output.rs").contains("pub fn capture("));
}

#[test]
fn public_sealed_dispatch_signature_requires_output_source_and_has_no_caller_limits() {
    let dispatch = include_str!("../../src/process_contract/orchestrator.rs")
        .split("pub(super) fn dispatch_input")
        .next()
        .expect("public dispatch source");
    assert!(
        dispatch.contains("output: &mut S") && dispatch.contains("S: ProcessOutputSourcePortV1")
    );
    assert!(
        !dispatch.contains("output_bounds: ProcessOutputBoundsV1,")
            && !dispatch.contains("output_caller: ProcessOutputCallerIdV1,")
    );
}

fn source_contains_helper(source: &str, helper: &str) -> bool {
    let scanned = scan_rust_source(source).expect("valid legacy test source");
    scanned.normalized_code.contains(helper) || scanned.string_literals.concat().contains(helper)
}

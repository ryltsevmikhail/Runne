use source_manifest::TASK6_INTEGRATION_SURFACES;

#[test]
fn integration_surface_negative_fixtures_are_detected() {
    assert!(!public_reexport_violations(
        "fixture",
        "pub use process_contract::ProcessOrchestratorV1;"
    )
    .is_empty());
    assert!(!manifest_violations("fixture", "[features]\nprocess = []").is_empty());
    assert!(!manifest_violations(
        "crates/runne-tools/Cargo.toml",
        "runne-platform-ports = { version = \"1\" }"
    )
    .is_empty());
}

#[test]
fn integration_surface_manifest_is_sorted_and_covers_only_task6_roots() {
    source_manifest::assert_sorted_unique(&TASK6_INTEGRATION_SURFACES, "integration surface");
    assert_eq!(TASK6_INTEGRATION_SURFACES.len(), 8);
    for (path, source) in TASK6_INTEGRATION_SURFACES {
        if path.ends_with("/src/lib.rs") {
            assert!(
                public_reexport_violations(path, source).is_empty(),
                "public Task6 composition authority:\n{}",
                public_reexport_violations(path, source).join("\n")
            );
        } else {
            assert!(
                manifest_violations(path, source).is_empty(),
                "forbidden Task6 manifest activation:\n{}",
                manifest_violations(path, source).join("\n")
            );
        }
    }
}

#[test]
fn task6_roots_exclude_legacy_bypass_symbols_even_when_split() {
    let legacy = [
        "ProcessToolExecutor::start",
        "ProcessBroker::prepare_contained",
        "ProcessLauncher",
    ];
    source_manifest::assert_sources_exclude(
        &source_manifest::PROCESS_CONTRACT_SOURCES,
        &legacy.map(str::to_owned),
        &[],
    );

    let fixture = [("fixture", "ProcessBroker /* split */ :: prepare_contained();")];
    let violations = source_manifest::source_violations(&fixture, &[legacy[1].to_owned()], &[]);
    assert_eq!(violations, ["fixture: ProcessBroker::prepare_contained"]);
}

fn public_reexport_violations(path: &str, source: &str) -> Vec<String> {
    let composition = [
        "ProcessOrchestratorV1",
        "ProcessClaimJournalPort",
        "ProcessControlPortV1",
    ];
    source
        .split("pub use")
        .skip(1)
        .filter_map(|reexport| reexport.split(';').next())
        .flat_map(|reexport| {
            composition
                .iter()
                .filter(move |&symbol| reexport.contains(symbol))
                .map(move |symbol| format!("{path}: {symbol}"))
        })
        .collect()
}

fn manifest_violations(path: &str, source: &str) -> Vec<String> {
    let dependency = "runne-platform-ports";
    let expected = format!("{dependency} = {{ path = \"../runne-platform-ports\" }}");
    let dependency_lines = source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(dependency))
        .collect::<Vec<_>>();
    let mut violations = forbidden_manifest_activations(path, source);
    if path == "crates/runne-platform-ports/Cargo.toml" {
        violations.extend(
            dependency_lines
                .iter()
                .map(|line| format!("{path}: unexpected {dependency}: {line}")),
        );
    } else if dependency_lines != [expected.as_str()] {
        violations.push(format!("{path}: expected exactly `{expected}`"));
    }
    violations
}

fn forbidden_manifest_activations(path: &str, source: &str) -> Vec<String> {
    let forbidden = [
        ["pro", "cess"].concat(),
        "native".to_owned(),
        "shell".to_owned(),
        "container".to_owned(),
        "renderer".to_owned(),
        "command".to_owned(),
    ];
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(|line| {
            let lowered = line.to_ascii_lowercase();
            forbidden
                .iter()
                .filter(move |&token| lowered.contains(token))
                .map(move |_| format!("{path}: {line}"))
        })
        .collect()
}

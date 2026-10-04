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
    let linux_rustix = "[target.'cfg(target_os = \"linux\")'.dependencies]\nrustix = { version = \"=1.1.4\", features = [\"fs\", \"process\"] }";
    assert!(forbidden_manifest_activations("crates/runne-platform/Cargo.toml", linux_rustix).is_empty());
    assert!(!forbidden_manifest_activations(
        "crates/runne-platform/Cargo.toml",
        &format!("{linux_rustix}\n[features]\nprocess = []")
    )
    .is_empty());
    for changed in [
        "[dependencies]\nrustix = { version = \"=1.1.4\", features = [\"fs\", \"process\"] }",
        "[target.'cfg(target_os = \"linux\")'.dependencies]\nrustix = { version = \"=1.1.5\", features = [\"fs\", \"process\"] }",
        "[target.'cfg(target_os = \"linux\")'.dependencies]\nrustix = { version = \"=1.1.4\", features = [\"fs\", \"process\", \"extra\"] }",
    ] {
        assert!(!forbidden_manifest_activations("crates/runne-platform/Cargo.toml", changed).is_empty());
    }
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
    let linux_dependencies = "[target.'cfg(target_os = \"linux\")'.dependencies]";
    let allowed_rustix = "rustix = { version = \"=1.1.4\", features = [\"fs\", \"process\"] }";
    let mut in_linux_dependencies = false;
    let mut allowed_rustix_count = 0;
    let mut violations = Vec::new();
    for line in source.lines().map(str::trim) {
        if line.starts_with('[') {
            in_linux_dependencies = line == linux_dependencies;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if path == "crates/runne-platform/Cargo.toml"
            && line == allowed_rustix
            && in_linux_dependencies
        {
            allowed_rustix_count += 1;
            continue;
        }
        let lowered = line.to_ascii_lowercase();
        for token in &forbidden {
            if lowered.contains(token) {
                violations.push(format!("{path}: {line}"));
            }
        }
    }
    if path == "crates/runne-platform/Cargo.toml" && allowed_rustix_count != 1 {
        violations.push(format!(
            "{path}: expected exactly one target-Linux Rustix implementation dependency"
        ));
    }
    violations
}

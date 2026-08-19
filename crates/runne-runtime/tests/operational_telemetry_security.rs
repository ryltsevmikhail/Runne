use runne_runtime::provider_execution::RuntimeProviderExecutionError;

#[test]
fn runtime_recovery_errors_are_fieldless_and_observer_port_carries_no_payload() {
    let error = RuntimeProviderExecutionError::PersistenceUnavailable;
    for marker in [
        "task3-prompt-marker",
        "task3-output-marker",
        "task3-provider-body-marker",
        "task3-sse-marker",
        "task3-raw-error-marker",
    ] {
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
    }
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../runne-application/src/provider/operational.rs"),
    )
    .unwrap();
    let start = source.find("pub trait ProviderRecoveryObserver").unwrap();
    let opening = source[start..].find('{').unwrap() + start;
    let mut depth = 0;
    let mut closing = opening;
    for (offset, byte) in source.as_bytes()[opening..].iter().enumerate() {
        depth += match byte {
            b'{' => 1,
            b'}' => -1,
            _ => 0,
        };
        if depth == 0 {
            closing = opening + offset;
            break;
        }
    }
    let observer: String = source[opening + 1..closing].split_whitespace().collect();
    assert_eq!(observer.matches("fn").count(), 1);
    assert_eq!(
        observer,
        "fnobserve_recovered_terminal_output(&self)->Result<(),ProviderRecoveryObserverError>;"
    );
    for forbidden in ["type", "const", "String", "&[u8]", "Vec<", "Box<", "dyn"] {
        assert!(
            !observer.contains(forbidden),
            "observer contains {forbidden}"
        );
    }
}

#[test]
fn runtime_recovery_telemetry_seam_has_no_observability_or_store_dependency() {
    for path in [
        "src/provider_execution_parts/part_01.rs",
        "src/provider_execution_parts/part_04.rs",
    ] {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap();
        for forbidden in [
            "runne_observability",
            "runne_store",
            "serde_json::Value",
            "HashMap",
            "BTreeMap",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}

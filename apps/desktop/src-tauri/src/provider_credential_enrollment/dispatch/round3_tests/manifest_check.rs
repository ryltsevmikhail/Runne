fn manifest(source: &str) -> toml::Value {
    toml::from_str(source).expect("valid desktop manifest")
}

fn dependency_has_test_support(dependency: &toml::Value) -> bool {
    dependency
        .get("features")
        .and_then(toml::Value::as_array)
        .is_some_and(|features| {
            features
                .iter()
                .any(|feature| feature.as_str() == Some("test-support"))
        })
}

fn dependency_table_has_test_support(table: Option<&toml::Value>) -> bool {
    table
        .and_then(toml::Value::as_table)
        .is_some_and(|dependencies| dependencies.values().any(dependency_has_test_support))
}

fn production_dependencies_enable_test_support(manifest: &toml::Value) -> bool {
    if dependency_table_has_test_support(manifest.get("dependencies"))
        || dependency_table_has_test_support(manifest.get("build-dependencies"))
    {
        return true;
    }
    manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| {
            targets.values().any(|target| {
                dependency_table_has_test_support(target.get("dependencies"))
                    || dependency_table_has_test_support(target.get("build-dependencies"))
            })
        })
}

fn feature_forwarding_enables_platform_test_support(manifest: &toml::Value) -> bool {
    manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .is_some_and(|features| {
            features.values().any(|value| {
                value.as_array().is_some_and(|values| {
                    values.iter().any(|feature| {
                        feature.as_str() == Some("runne-platform-desktop/test-support")
                    })
                })
            })
        })
}

#[test]
fn platform_enrollment_fixtures_are_dev_only_dependencies() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("desktop manifest");
    let parsed = manifest(&source);
    assert!(!production_dependencies_enable_test_support(&parsed));
    assert!(!feature_forwarding_enables_platform_test_support(&parsed));
    let dev_platform = parsed
        .get("dev-dependencies")
        .and_then(|dependencies| dependencies.get("runne-platform-desktop"))
        .expect("dev platform dependency");
    assert!(dependency_has_test_support(dev_platform));
}

#[test]
fn manifest_check_scopes_dependency_features_and_handles_target_and_build_tables() {
    let binary_requirement = manifest(
        "[[bin]]\nrequired-features = [\"test-support\"]\n[features]\ntest-support = [\"runne-app-core/test-support\"]\n[dependencies]\nrunne-platform-desktop = { features = [\"protected-channel-integration\"] }",
    );
    assert!(!production_dependencies_enable_test_support(
        &binary_requirement
    ));

    for source in [
        "[dependencies]\nrunne-platform-desktop = { features = [\"protected-channel-integration\", \"test-support\"] }",
        "[target.'cfg(unix)'.dependencies]\nrunne-platform-desktop = { features = [\"test-support\"] }",
        "[build-dependencies]\nrunne-platform-desktop = { features = [\"test-support\"] }",
        "[target.'cfg(unix)'.build-dependencies]\nrunne-platform-desktop = { features = [\"test-support\"] }",
        "[dependencies.runne-platform-desktop]\nfeatures = [\"test-support\"]",
        "[target.'cfg(unix)'.dependencies.runne-platform-desktop]\nfeatures = [\"test-support\"]",
    ] {
        assert!(production_dependencies_enable_test_support(&manifest(
            source
        )));
    }
    assert!(!production_dependencies_enable_test_support(&manifest(
        "[dev-dependencies]\nrunne-platform-desktop = { features = [\"test-support\"] }",
    )));
    assert!(feature_forwarding_enables_platform_test_support(&manifest(
        "[features]\nfixture = [\"runne-platform-desktop/test-support\"]",
    )));
}

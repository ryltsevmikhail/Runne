use std::path::{Path, PathBuf};

const PRODUCTION_FILES: &[&str] = &[
    "application/workspace_internal/provider_dependencies.rs",
    "canonical_provider.rs",
    "canonical_provider/composition.rs",
    "canonical_provider/composition/credential_reader.rs",
    "canonical_provider/credential_reader.rs",
    "canonical_provider/credential_versions.rs",
    "canonical_provider/effect_adapter.rs",
    "canonical_provider/readiness.rs",
    "doctor.rs",
];

const FORBIDDEN: &[&str] = &[
    "NativeProviderCredentialStore",
    "NativeProviderCredentialVersionStore",
    "ProviderCredentialStore",
    "NativeCredentialAuthority",
    "LoopbackCredentialVersionStoreFactory",
    ".create_version(",
    ".delete_version(",
    ".load_provider_credential_source(",
    ".provider_credential_status(",
];

#[test]
fn daemon_has_no_native_writer_capability() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    for relative in PRODUCTION_FILES {
        collect_violations(&source, relative, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "production daemon retains native writer capability:\n{}",
        violations.join("\n")
    );
}

#[test]
fn runned_cannot_call_writer() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("provider-credential-broker-writer"),
        "runned must not enable the runne-secure-store writer feature"
    );
}

fn collect_violations(source: &Path, relative: &str, violations: &mut Vec<String>) {
    let path = source.join(relative);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut fixture_only = false;
    for (index, line) in contents.lines().enumerate() {
        if line.contains("fixture-only capability begin") {
            fixture_only = true;
            continue;
        }
        if line.contains("fixture-only capability end") {
            fixture_only = false;
            continue;
        }
        if fixture_only {
            continue;
        }
        for forbidden in FORBIDDEN {
            if line.contains(forbidden) {
                violations.push(format!(
                    "{}:{}: {}",
                    display_path(&path).display(),
                    index + 1,
                    forbidden
                ));
            }
        }
    }
}

fn display_path(path: &Path) -> PathBuf {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .to_path_buf()
}

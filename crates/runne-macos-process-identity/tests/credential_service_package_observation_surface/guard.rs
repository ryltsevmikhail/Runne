use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

#[cfg(test)]
#[path = "guard/ast_tests.rs"]
mod ast_tests;
#[path = "guard/calls.rs"]
mod calls;
#[path = "guard/receiver_calls.rs"]
mod receiver_calls;
#[path = "guard/receiver_facts.rs"]
mod receiver_facts;
#[path = "guard/receiver_helpers.rs"]
mod receiver_helpers;
#[path = "guard/receivers.rs"]
mod receivers;
#[path = "guard/source_edge_macros.rs"]
mod source_edge_macros;
#[path = "guard/source_edges.rs"]
mod source_edges;
#[path = "guard/syntax.rs"]
mod syntax;
#[path = "guard/token_calls.rs"]
mod token_calls;

pub use calls::{count_credential_service_calls, count_workspace_credential_service_calls};

pub fn collect_workspace_production_sources(workspace: &Path, facade: &Path) -> Vec<String> {
    let workspace = std::fs::canonicalize(workspace).unwrap_or_else(|error| {
        panic!("cannot resolve workspace {}: {error}", workspace.display())
    });
    let facade = std::fs::canonicalize(facade).unwrap_or_else(|_| facade.to_path_buf());
    let packages = production_packages(&workspace);
    let roots = packages
        .iter()
        .map(|package| package.root.clone())
        .collect::<Vec<_>>();
    let mut pending = packages
        .iter()
        .flat_map(|package| package.targets.clone())
        .collect::<Vec<_>>();
    let mut paths = HashSet::new();
    while let Some(path) = pending.pop() {
        let canonical = std::fs::canonicalize(&path)
            .unwrap_or_else(|error| panic!("cannot resolve source {}: {error}", path.display()));
        assert!(
            roots.iter().any(|root| canonical.starts_with(root)),
            "production source escaped package roots: {}",
            canonical.display()
        );
        if canonical == facade || !paths.insert(canonical.clone()) {
            continue;
        }
        let source = std::fs::read_to_string(&canonical)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", canonical.display()));
        pending.extend(source_edges::source_edges(&canonical, &source));
    }
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    let mut inventory = paths.iter().cloned().collect::<HashSet<_>>();
    inventory.insert(facade);
    paths
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            source_edges::validate_source_edges(&path, &source, &inventory);
            source
        })
        .collect()
}

pub fn is_workspace_production_source(path: &Path, facade: &Path) -> bool {
    path != facade
        && path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "inc")
}

pub fn production_text(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

struct ProductionPackage {
    root: PathBuf,
    targets: Vec<PathBuf>,
}

fn production_packages(workspace: &Path) -> Vec<ProductionPackage> {
    let manifest = workspace.join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .unwrap_or_else(|error| panic!("cannot run cargo metadata: {error}"));
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("cargo metadata returned invalid JSON: {error}"));
    let metadata_packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("cargo metadata omitted packages"));
    let mut packages: Vec<ProductionPackage> = Vec::new();
    for package in metadata_packages {
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("cargo metadata package omitted targets"));
        let targets = targets
            .iter()
            .filter(|target| is_production_target(target))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            continue;
        }
        let manifest_path = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("cargo metadata package omitted manifest_path"));
        let root = Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| panic!("invalid package manifest path: {manifest_path}"));
        let root = std::fs::canonicalize(root).unwrap_or_else(|error| {
            panic!("cannot resolve package root {}: {error}", root.display())
        });
        assert!(
            root.starts_with(workspace),
            "production package escaped workspace: {}",
            root.display()
        );
        let source_paths = targets
            .iter()
            .map(|target| {
                let source = target
                    .get("src_path")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("cargo metadata target omitted src_path"));
                std::fs::canonicalize(source).unwrap_or_else(|error| {
                    panic!("cannot resolve target source {source}: {error}")
                })
            })
            .collect::<Vec<_>>();
        packages.push(ProductionPackage {
            root,
            targets: source_paths,
        });
    }
    packages.sort_by(|left, right| left.root.cmp(&right.root));
    packages.dedup_by(|left, right| left.root == right.root);
    assert!(
        !packages.is_empty(),
        "cargo metadata found no production package roots"
    );
    packages
}

fn is_production_target(target: &Value) -> bool {
    target
        .get("kind")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("cargo metadata target omitted kind"))
        .iter()
        .filter_map(Value::as_str)
        .any(|kind| matches!(kind, "lib" | "bin" | "cdylib" | "staticlib" | "proc-macro"))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{collect_workspace_production_sources, count_workspace_credential_service_calls};

    struct TemporaryWorkspace(PathBuf);

    impl TemporaryWorkspace {
        fn new() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "runne-observation-guard-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, source: &str) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, source).unwrap();
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryWorkspace {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn inventory_follows_cargo_targets_modules_includes_and_tauri_sources() {
        let workspace = TemporaryWorkspace::new();
        workspace.write(
            "Cargo.toml",
            r#"
                [workspace]
                members = ["crates/example", "apps/desktop/src-tauri"]
                resolver = "2"
            "#,
        );
        workspace.write(
            "crates/example/Cargo.toml",
            r#"
                [package]
                name = "example"
                version = "0.1.0"
                edition = "2021"
                [lib]
                path = "src/lib.rs"
                [[bin]]
                name = "test_fixture"
                path = "test_fixture/main.rs"
            "#,
        );
        workspace.write(
            "apps/desktop/src-tauri/Cargo.toml",
            r#"
                [package]
                name = "desktop"
                version = "0.1.0"
                edition = "2021"
                [[bin]]
                name = "desktop-test"
                path = "src/test_runtime.rs"
            "#,
        );
        let caller = "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; fn caller() { Pending::capture_current(); }";
        workspace.write(
            "crates/example/src/lib.rs",
            r#"
                #[path = "../outside.rs"] mod outside;
                macro_rules! load { ($path:literal) => { include!($path); } }
                include!("parts/direct_fixture.inc");
                load!("parts/macro_fixture.inc");
            "#,
        );
        workspace.write("crates/example/outside.rs", caller);
        workspace.write("crates/example/test_fixture/main.rs", caller);
        workspace.write("crates/example/src/parts/direct_fixture.inc", caller);
        workspace.write("crates/example/src/parts/macro_fixture.inc", caller);
        workspace.write("apps/desktop/src-tauri/src/test_runtime.rs", caller);

        let facade = workspace.path().join("crates/native/src/facade.rs");
        let sources = collect_workspace_production_sources(workspace.path(), &facade);
        assert_eq!(count_workspace_credential_service_calls(&sources), 5);
    }
}

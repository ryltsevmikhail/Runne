use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use super::inventory_macro_resolution::MacroDependencyKind;

pub(super) struct Package {
    pub(super) root: PathBuf,
    pub(super) targets: Vec<Target>,
    pub(super) dependencies: Vec<Dependency>,
}

pub(super) struct Target {
    pub(super) name: String,
    pub(super) source: PathBuf,
    pub(super) dependency_kind: MacroDependencyKind,
}

pub(super) struct Dependency {
    pub(super) visible_name: String,
    pub(super) root: PathBuf,
    pub(super) kind: MacroDependencyKind,
}

pub(super) fn production_packages(workspace: &Path) -> Vec<Package> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(workspace.join("Cargo.toml"))
        .output()
        .unwrap_or_else(|error| panic!("cannot run cargo metadata: {error}"));
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("cargo metadata returned invalid JSON: {error}"));
    let raw_packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata omitted packages");
    let library_names = dependency_library_names(raw_packages);
    let mut packages = raw_packages
        .iter()
        .filter_map(|package| package_from_metadata(workspace, package, &library_names))
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.root.cmp(&right.root));
    assert!(
        !packages.is_empty(),
        "cargo metadata found no production package roots"
    );
    packages
}

fn package_from_metadata(
    workspace: &Path,
    package: &Value,
    library_names: &HashMap<PathBuf, String>,
) -> Option<Package> {
    let targets = package["targets"]
        .as_array()
        .expect("cargo metadata package omitted targets")
        .iter()
        .filter(|target| is_production_target(target))
        .map(|target| Target {
            name: target["name"].as_str().expect("target omitted name").into(),
            source: std::fs::canonicalize(
                target["src_path"]
                    .as_str()
                    .expect("target omitted src_path"),
            )
            .expect("cannot resolve target source"),
            dependency_kind: target_dependency_kind(target),
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return None;
    }
    let manifest = package["manifest_path"]
        .as_str()
        .expect("package omitted manifest_path");
    let root = std::fs::canonicalize(Path::new(manifest).parent().expect("invalid manifest path"))
        .expect("cannot resolve package root");
    assert!(
        root.starts_with(workspace),
        "production package escaped workspace"
    );
    let dependencies = package["dependencies"]
        .as_array()
        .expect("cargo metadata package omitted dependencies")
        .iter()
        .filter_map(|dependency| dependency_from_metadata(dependency, library_names))
        .collect();
    Some(Package {
        root,
        targets,
        dependencies,
    })
}

fn dependency_from_metadata(
    dependency: &Value,
    library_names: &HashMap<PathBuf, String>,
) -> Option<Dependency> {
    let kind = match dependency["kind"].as_str() {
        None => MacroDependencyKind::Normal,
        Some("build") => MacroDependencyKind::Build,
        Some("dev") => return None,
        Some(kind) => panic!("unsupported Cargo dependency kind: {kind}"),
    };
    let path = dependency["path"].as_str()?;
    let root = std::fs::canonicalize(path).expect("cannot resolve dependency package root");
    let visible_name = dependency["rename"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| library_names.get(&root).cloned())
        .unwrap_or_else(|| dependency_name(dependency))
        .replace('-', "_");
    Some(Dependency {
        visible_name,
        root,
        kind,
    })
}

fn dependency_library_names(packages: &[Value]) -> HashMap<PathBuf, String> {
    packages
        .iter()
        .filter_map(|package| {
            let root = package_root(package);
            let mut names = package["targets"]
                .as_array()
                .expect("package target list omitted")
                .iter()
                .filter(|target| target_is_library(target))
                .map(|target| {
                    target["name"]
                        .as_str()
                        .expect("library target omitted name")
                        .to_owned()
                });
            let name = names.next()?;
            assert!(
                names.next().is_none(),
                "package has multiple library targets"
            );
            Some((root, name))
        })
        .collect()
}

fn package_root(package: &Value) -> PathBuf {
    let manifest = package["manifest_path"]
        .as_str()
        .expect("package omitted manifest_path");
    std::fs::canonicalize(Path::new(manifest).parent().expect("invalid manifest path"))
        .expect("cannot resolve package root")
}

fn dependency_name(dependency: &Value) -> String {
    dependency["name"]
        .as_str()
        .expect("dependency omitted name")
        .to_owned()
}

fn target_is_library(target: &Value) -> bool {
    target["kind"]
        .as_array()
        .expect("target omitted kind")
        .iter()
        .any(|kind| matches!(kind.as_str(), Some("lib" | "proc-macro")))
}

fn target_dependency_kind(target: &Value) -> MacroDependencyKind {
    if target["kind"]
        .as_array()
        .expect("target omitted kind")
        .iter()
        .any(|kind| kind.as_str() == Some("custom-build"))
    {
        MacroDependencyKind::Build
    } else {
        MacroDependencyKind::Normal
    }
}

fn is_production_target(target: &Value) -> bool {
    target["kind"]
        .as_array()
        .expect("target omitted kind")
        .iter()
        .filter_map(Value::as_str)
        .any(|kind| {
            matches!(
                kind,
                "lib" | "bin" | "cdylib" | "staticlib" | "proc-macro" | "custom-build"
            )
        })
}

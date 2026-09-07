use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cargo_metadata::{MetadataCommand, TargetKind};
use syn::{File, Item};

use super::edges::{
    Child, collect_includes, collect_raw_includes, collect_raw_includes_from_text,
    external_module_path,
};
use super::source_audit::{SourceUnit, item_attrs, item_is_test_only};

struct Inventory {
    sources: BTreeMap<PathBuf, SourceUnit>,
    active: BTreeSet<PathBuf>,
    findings: Vec<String>,
}

pub(super) fn compiled_source_inventory(workspace: &Path) -> Vec<SourceUnit> {
    inventory_for_manifest(&workspace.join("Cargo.toml"))
}

pub(super) fn inventory_for_manifest(manifest: &Path) -> Vec<SourceUnit> {
    let metadata = MetadataCommand::new()
        .manifest_path(manifest)
        .no_deps()
        .exec()
        .unwrap_or_else(|error| panic!("cargo metadata failed for source guard: {error}"));
    let mut inventory = Inventory {
        sources: BTreeMap::new(),
        active: BTreeSet::new(),
        findings: Vec::new(),
    };
    for package in metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
    {
        for target in &package.targets {
            let test_only = target
                .kind
                .iter()
                .any(|kind| matches!(kind, TargetKind::Test | TargetKind::Bench));
            inventory.walk(target.src_path.as_std_path(), test_only);
        }
    }
    assert!(
        inventory.findings.is_empty(),
        "source inventory was incomplete: {:?}",
        inventory.findings
    );
    inventory.sources.into_values().collect()
}

impl Inventory {
    fn walk(&mut self, path: &Path, test_only: bool) {
        let path = path.to_path_buf();
        if self.active.contains(&path) {
            self.findings
                .push(format!("recursive source inclusion at {}", path.display()));
            return;
        }
        let should_read = self
            .sources
            .get(&path)
            .is_none_or(|existing| existing.test_only && !test_only);
        if !should_read {
            return;
        }
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                self.findings
                    .push(format!("cannot read {}: {error}", path.display()));
                return;
            }
        };
        self.sources.insert(
            path.clone(),
            SourceUnit {
                path: path.clone(),
                source: source.clone(),
                test_only,
            },
        );
        self.active.insert(path.clone());
        for child in source_children(&path, &source, test_only, &mut self.findings) {
            self.walk(&child.path, child.test_only);
        }
        self.active.remove(&path);
    }
}

fn source_children(
    path: &Path,
    source: &str,
    inherited_test_only: bool,
    findings: &mut Vec<String>,
) -> Vec<Child> {
    let Ok(file) = syn::parse_file(source) else {
        return collect_raw_includes(path, source, inherited_test_only, findings);
    };
    let mut children = Vec::new();
    collect_items(path, &file, inherited_test_only, &mut children, findings);
    children
}

fn collect_items(
    path: &Path,
    file: &File,
    inherited_test_only: bool,
    children: &mut Vec<Child>,
    findings: &mut Vec<String>,
) {
    for item in &file.items {
        let item_test_only = inherited_test_only || item_is_test_only(item_attrs(item));
        if item_test_only {
            continue;
        }
        match item {
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    let nested_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: nested.clone(),
                    };
                    collect_items(path, &nested_file, item_test_only, children, findings);
                } else if let Some(module_path) =
                    external_module_path(path, &module.ident.to_string(), module.attrs.as_slice())
                {
                    children.push(Child {
                        path: module_path,
                        test_only: item_test_only,
                    });
                } else {
                    findings.push(format!(
                        "cannot resolve module {} declared by {}",
                        module.ident,
                        path.display()
                    ));
                }
            }
            Item::Macro(item) => {
                collect_raw_includes_from_text(
                    path,
                    &item.mac.tokens.to_string(),
                    inherited_test_only,
                    children,
                    findings,
                );
            }
            _ => collect_includes(path, item, inherited_test_only, children, findings),
        }
    }
}

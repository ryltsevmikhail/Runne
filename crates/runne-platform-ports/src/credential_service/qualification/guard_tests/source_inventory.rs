use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cargo_metadata::{MetadataCommand, TargetKind};
use syn::{File, Item};

use super::edges::{
    Child, collect_includes, collect_raw_includes, collect_raw_includes_from_text,
    external_module_path, is_compiler_include,
};
use super::source_audit::{SourceUnit, item_attrs, item_is_test_only};

#[path = "source_inventory_trust.rs"]
mod source_inventory_trust;

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
        let mut trusted_external_roots = trusted_dependency_roots(&metadata, package);
        trusted_external_roots.insert("std".to_owned());
        for target in &package.targets {
            let test_only = target
                .kind
                .iter()
                .any(|kind| matches!(kind, TargetKind::Test | TargetKind::Bench));
            inventory.walk(
                target.src_path.as_std_path(),
                test_only,
                &trusted_external_roots,
            );
        }
    }
    assert!(
        inventory.findings.is_empty(),
        "source inventory was incomplete: {:?}",
        inventory.findings
    );
    inventory.sources.into_values().collect()
}

fn trusted_dependency_roots(
    metadata: &cargo_metadata::Metadata,
    package: &cargo_metadata::Package,
) -> BTreeSet<String> {
    let Some(node) = metadata
        .resolve
        .as_ref()
        .and_then(|resolve| resolve.nodes.iter().find(|node| node.id == package.id))
    else {
        return BTreeSet::new();
    };
    let mut grouped = BTreeMap::<String, Vec<&cargo_metadata::Package>>::new();
    for dependency in &node.deps {
        if let Some(resolved) = metadata
            .packages
            .iter()
            .find(|item| item.id == dependency.pkg)
        {
            grouped
                .entry(dependency.name.replace('-', "_"))
                .or_default()
                .push(resolved);
        }
    }
    grouped
        .into_iter()
        .filter_map(|(visible, resolved)| {
            resolved
                .iter()
                .all(|package| {
                    source_inventory_trust::is_trusted_macro_package(&package.name)
                        && package.source.as_ref().is_some_and(|source| {
                            source.repr == "registry+https://github.com/rust-lang/crates.io-index"
                        })
                })
                .then_some(visible)
        })
        .collect()
}

impl Inventory {
    fn walk(&mut self, path: &Path, test_only: bool, trusted_external_roots: &BTreeSet<String>) {
        let path = path.to_path_buf();
        if self.active.contains(&path) {
            self.findings
                .push(format!("recursive source inclusion at {}", path.display()));
            return;
        }
        if let Some(existing) = self.sources.get_mut(&path) {
            let merged_test_only = existing.test_only && test_only;
            let merged_roots = existing
                .trusted_external_roots
                .intersection(trusted_external_roots)
                .cloned()
                .collect::<BTreeSet<_>>();
            if existing.test_only == merged_test_only
                && existing.trusted_external_roots == merged_roots
            {
                return;
            }
            existing.test_only = merged_test_only;
            existing.trusted_external_roots = merged_roots;
        }
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                self.findings
                    .push(format!("cannot read {}: {error}", path.display()));
                return;
            }
        };
        let mut context_roots = trusted_external_roots.clone();
        if let Ok(file) = syn::parse_file(&source) {
            context_roots.retain(|root| !super::source_audit::source_shadows_root(&file, root));
        }
        self.sources
            .entry(path.clone())
            .or_insert_with(|| SourceUnit {
                path: path.clone(),
                source: source.clone(),
                test_only,
                trusted_external_roots: context_roots.clone(),
            });
        if let Some(unit) = self.sources.get_mut(&path) {
            unit.trusted_external_roots = unit
                .trusted_external_roots
                .intersection(&context_roots)
                .cloned()
                .collect();
        }
        let effective_roots = self.sources[&path].trusted_external_roots.clone();
        self.active.insert(path.clone());
        for child in source_children(&path, &source, test_only, &mut self.findings) {
            self.walk(&child.path, child.test_only, &effective_roots);
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
    collect_items(
        path,
        &file,
        None,
        inherited_test_only,
        &mut children,
        findings,
    );
    children
}

fn collect_items(
    path: &Path,
    file: &File,
    module_dir: Option<&Path>,
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
                if module.attrs.iter().any(|attr| {
                    attr.path().is_ident("cfg_attr")
                        && attr
                            .meta
                            .require_list()
                            .is_ok_and(|list| list.tokens.to_string().contains("path"))
                }) {
                    findings.push(format!("conditional module path in {}", path.display()));
                    continue;
                }
                if let Some((_, nested)) = &module.content {
                    let nested_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: nested.clone(),
                    };
                    let nested_dir = module_dir.map_or_else(
                        || inline_module_dir(path, &module.ident.to_string()),
                        |directory| directory.join(module.ident.to_string()),
                    );
                    collect_items(
                        path,
                        &nested_file,
                        Some(&nested_dir),
                        item_test_only,
                        children,
                        findings,
                    );
                } else if let Some(module_path) = module_dir
                    .and_then(|directory| {
                        module_path_from_dir(directory, &module.ident.to_string(), &module.attrs)
                    })
                    .or_else(|| {
                        external_module_path(
                            path,
                            &module.ident.to_string(),
                            module.attrs.as_slice(),
                        )
                    })
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
            Item::Macro(macro_item) if is_compiler_include(&macro_item.mac.path) => {
                collect_includes(path, item, inherited_test_only, children, findings);
            }
            Item::Macro(item) => collect_raw_includes_from_text(
                path,
                &item.mac.tokens.to_string(),
                inherited_test_only,
                children,
                findings,
            ),
            _ => collect_includes(path, item, inherited_test_only, children, findings),
        }
    }
}

fn inline_module_dir(path: &Path, module: &str) -> PathBuf {
    let directory = path.parent().unwrap_or(path);
    match path.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => directory.join(module),
        _ => directory
            .join(path.file_stem().unwrap_or_default())
            .join(module),
    }
}

fn module_path_from_dir(
    directory: &Path,
    module: &str,
    attrs: &[syn::Attribute],
) -> Option<PathBuf> {
    let explicit = attrs.iter().find_map(|attribute| match &attribute.meta {
        syn::Meta::NameValue(value) if value.path.is_ident("path") => match &value.value {
            syn::Expr::Lit(value) => match &value.lit {
                syn::Lit::Str(value) => Some(directory.join(value.value())),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    });
    explicit.or_else(|| {
        let flat = directory.join(format!("{module}.rs"));
        flat.is_file().then_some(flat).or_else(|| {
            let nested = directory.join(module).join("mod.rs");
            nested.is_file().then_some(nested)
        })
    })
}

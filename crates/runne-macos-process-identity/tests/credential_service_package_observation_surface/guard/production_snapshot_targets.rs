use std::collections::HashSet;
use std::path::PathBuf;

use super::production_metadata::Package;
use super::source_edge_macros::MacroDefinitions;

#[path = "production_snapshot_targets/provenance.rs"]
mod provenance;

pub(super) struct TargetSelection {
    pub(super) packages: HashSet<PathBuf>,
    pub(super) sources: HashSet<PathBuf>,
}

impl TargetSelection {
    pub(super) fn includes(&self, source: &std::path::Path) -> bool {
        self.sources.contains(source)
    }
}

/// Selects every workspace package that can depend on the unique definition
/// package. Cargo metadata provides the package graph; Rust syntax then cannot
/// cause a consumer to disappear through an alias, re-export, or macro body.
pub(super) fn select_target_consumers(
    packages: &[Package],
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
) -> TargetSelection {
    let target = super::source_model::CanonicalTarget::default();
    let canonical_type = target.type_path.last().expect("canonical target type");
    let definitions = packages
        .iter()
        .filter(|package| {
            package
                .targets
                .iter()
                .any(|unit| unit.name.replace('-', "_") == target.crate_name)
        })
        .map(|package| package.root.clone())
        .collect::<HashSet<_>>();
    if definitions.is_empty() {
        return TargetSelection {
            packages: packages
                .iter()
                .map(|package| package.root.clone())
                .collect(),
            sources: sources.keys().cloned().collect(),
        };
    }
    assert_eq!(
        definitions.len(),
        1,
        "canonical target package is ambiguous"
    );

    let relevant = relevant_packages(
        packages,
        sources,
        macros,
        definitions.clone(),
        &definitions,
        canonical_type,
    );
    let selected_packages = relevant
        .iter()
        .filter(|root| !definitions.contains(*root))
        .cloned()
        .collect::<HashSet<_>>();
    let sources = selected_target_sources(
        &selected_packages,
        &relevant,
        packages,
        sources,
        macros,
        &definitions,
        canonical_type,
    );
    TargetSelection {
        packages: selected_packages,
        sources,
    }
}

fn relevant_packages(
    packages: &[Package],
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    mut relevant: HashSet<PathBuf>,
    definitions: &HashSet<PathBuf>,
    canonical_type: &str,
) -> HashSet<PathBuf> {
    loop {
        let mut changed = false;
        for package in packages {
            if !relevant.contains(&package.root)
                && package_references_relevant_dependency(
                    package,
                    &relevant,
                    sources,
                    macros,
                    definitions,
                    canonical_type,
                )
            {
                changed |= relevant.insert(package.root.clone());
            }
        }
        if !changed {
            break;
        }
    }
    relevant
}

fn selected_target_sources(
    selected_packages: &HashSet<PathBuf>,
    relevant: &HashSet<PathBuf>,
    packages: &[Package],
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    definitions: &HashSet<PathBuf>,
    canonical_type: &str,
) -> HashSet<PathBuf> {
    let mut pending = packages
        .iter()
        .filter(|package| selected_packages.contains(&package.root))
        .flat_map(|package| {
            package
                .targets
                .iter()
                .filter(|target| {
                    target_references_relevant_dependency(
                        package,
                        target,
                        relevant,
                        sources,
                        macros,
                        definitions,
                        canonical_type,
                    )
                })
                .map(|target| target.source.clone())
        })
        .collect::<Vec<_>>();
    source_closure(&mut pending, sources, macros)
}

fn package_references_relevant_dependency(
    package: &Package,
    relevant: &HashSet<PathBuf>,
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    definitions: &HashSet<PathBuf>,
    canonical_type: &str,
) -> bool {
    package.targets.iter().any(|target| {
        target_references_relevant_dependency(
            package,
            target,
            relevant,
            sources,
            macros,
            definitions,
            canonical_type,
        )
    })
}

fn target_references_relevant_dependency(
    package: &Package,
    target: &super::production_metadata::Target,
    relevant: &HashSet<PathBuf>,
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    definitions: &HashSet<PathBuf>,
    canonical_type: &str,
) -> bool {
    let mut pending = vec![target.source.clone()];
    let closure = source_closure(&mut pending, sources, macros);
    let relevant_dependencies = package
        .dependencies
        .iter()
        .filter(|dependency| relevant.contains(&dependency.root))
        .collect::<Vec<_>>();
    relevant_dependencies.iter().any(|dependency| {
        relevant.contains(&dependency.root)
            && provenance::references(
                &closure,
                sources,
                &dependency.visible_name,
                definitions
                    .contains(&dependency.root)
                    .then_some(canonical_type),
            )
    }) || (!relevant_dependencies.is_empty()
        && provenance::generation::possible(
            &closure,
            sources,
            macros,
            package
                .dependencies
                .iter()
                .map(|dependency| &dependency.visible_name),
        ))
}

fn source_closure(
    pending: &mut Vec<PathBuf>,
    sources: &std::collections::HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
) -> HashSet<PathBuf> {
    let mut selected = HashSet::new();
    while let Some(path) = pending.pop() {
        if !selected.insert(path.clone()) {
            continue;
        }
        let source = sources.get(&path).unwrap_or_else(|| {
            panic!("selected Cargo target source is absent: {}", path.display())
        });
        pending.extend(
            super::source_edges::source_edge_records(&path, source, macros, false)
                .into_iter()
                .map(|edge| edge.target),
        );
    }
    selected
}

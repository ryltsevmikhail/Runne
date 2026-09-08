use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::ProductionSnapshot;
use super::production_metadata::{Package, production_packages};
use super::source_edge_macros::MacroDefinitions;
use super::source_model::{
    CrateUnit, OpaqueSourceMacro, PackageId, SourceEdge, SourceEdgeKind, SourceGraph, SourceId,
    SourceNode, SourceOrigin, SyntaxId, TargetId,
};

pub(super) fn collect(workspace: &Path, facade: &Path) -> ProductionSnapshot {
    collect_with_consumer_filter(workspace, facade, false)
}

pub(super) fn collect_consumers(workspace: &Path, facade: &Path) -> ProductionSnapshot {
    collect_with_consumer_filter(workspace, facade, true)
}

fn collect_with_consumer_filter(
    workspace: &Path,
    facade: &Path,
    consumers_only: bool,
) -> ProductionSnapshot {
    let workspace = std::fs::canonicalize(workspace).unwrap_or_else(|error| {
        panic!("cannot resolve workspace {}: {error}", workspace.display())
    });
    let facade = std::fs::canonicalize(facade).unwrap_or_else(|_| facade.to_path_buf());
    let packages = production_packages(&workspace);
    let initial = packages
        .iter()
        .flat_map(|package| package.targets.iter().map(|target| target.source.clone()))
        .chain(std::iter::once(facade.clone()))
        .collect::<Vec<_>>();
    let mut macros = MacroDefinitions::default();
    for package in &packages {
        for dependency in &package.dependencies {
            super::inventory_macro_scope::register_dependency(
                &mut macros,
                &package.root,
                dependency.kind,
                &dependency.visible_name,
                &dependency.root,
            );
        }
        for target in &package.targets {
            super::inventory_macro_scope::register_source_context(
                &mut macros,
                &target.source,
                &package.root,
                target.dependency_kind,
            );
        }
    }
    let (sources, macros) = collect_sources(initial, macros);
    assert!(
        sources.contains_key(&facade),
        "facade omitted from snapshot"
    );
    let opaque_source_macros = validate_sources(&sources, &macros);
    let graph = build_graph(
        &packages,
        &sources,
        &macros,
        opaque_source_macros,
        consumers_only,
    );
    ProductionSnapshot { graph, macros }
}

fn collect_sources(
    mut pending: Vec<PathBuf>,
    mut definitions: MacroDefinitions,
) -> (HashMap<PathBuf, String>, MacroDefinitions) {
    let mut sources = HashMap::new();
    loop {
        while let Some(path) = pending.pop() {
            let canonical = std::fs::canonicalize(&path).unwrap_or_else(|error| {
                panic!("cannot resolve source {}: {error}", path.display())
            });
            if sources.contains_key(&canonical) {
                continue;
            }
            let source = std::fs::read_to_string(&canonical)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", canonical.display()));
            definitions.extend(&canonical, &source);
            let targets =
                super::source_edges::source_edges(&canonical, &source, &definitions, true);
            inherit_contexts_and_enqueue(&mut pending, &mut definitions, &canonical, targets);
            sources.insert(canonical, source);
        }
        for (path, source) in &sources {
            let targets = super::source_edges::source_edges(path, source, &definitions, true);
            inherit_contexts_and_enqueue(&mut pending, &mut definitions, path, targets);
        }
        pending.retain(|path| !sources.contains_key(path));
        if pending.is_empty() {
            return (sources, definitions);
        }
    }
}

fn inherit_contexts_and_enqueue(
    pending: &mut Vec<PathBuf>,
    definitions: &mut MacroDefinitions,
    source: &Path,
    targets: Vec<PathBuf>,
) {
    for target in targets {
        super::inventory_macro_scope::inherit_source_contexts(definitions, source, &target);
        pending.push(target);
    }
}

fn validate_sources(
    sources: &HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
) -> Vec<OpaqueSourceMacro> {
    let inventory = sources.keys().cloned().collect::<HashSet<_>>();
    sources
        .iter()
        .flat_map(|(path, source)| {
            super::source_edges::validate_source_edges(path, source, &inventory, macros)
        })
        .collect()
}

fn build_graph(
    packages: &[Package],
    sources: &HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    opaque_source_macros: Vec<OpaqueSourceMacro>,
    consumers_only: bool,
) -> SourceGraph {
    let selection = consumers_only.then(|| {
        super::production_snapshot_targets::select_target_consumers(packages, sources, macros)
    });
    let mut graph = SourceGraph {
        opaque_source_macros,
        ..SourceGraph::default()
    };
    for (package_ordinal, package) in packages.iter().enumerate() {
        if selection
            .as_ref()
            .is_some_and(|selection| !selection.packages.contains(&package.root))
        {
            continue;
        }
        let package_id =
            PackageId(u32::try_from(package_ordinal).expect("package count exceeds u32"));
        for target in &package.targets {
            if selection
                .as_ref()
                .is_some_and(|selection| !selection.includes(&target.source))
            {
                continue;
            }
            let target_id =
                TargetId(u32::try_from(graph.crates.len()).expect("target count exceeds u32"));
            let root = add_node(
                &mut graph,
                sources,
                package_id,
                target_id,
                &target.source,
                SourceOrigin::RustModule,
            );
            graph.crates.push(CrateUnit {
                package: package_id,
                target: target_id,
                crate_name: target.name.replace('-', "_"),
                root,
            });
            expand_node(
                &mut graph,
                sources,
                macros,
                root,
                &[],
                std::slice::from_ref(&target.source),
                selection.as_ref().map(|selection| &selection.sources),
            );
        }
    }
    graph.opaque_source_macros.retain(|opaque| {
        graph
            .nodes
            .iter()
            .any(|node| node.canonical_path == opaque.from)
    });
    graph
}

fn add_node(
    graph: &mut SourceGraph,
    sources: &HashMap<PathBuf, String>,
    package: PackageId,
    target: TargetId,
    path: &Path,
    origin: SourceOrigin,
) -> SourceId {
    let id = SourceId(u32::try_from(graph.nodes.len()).expect("source count exceeds u32"));
    graph.nodes.push(SourceNode {
        id,
        package,
        target,
        canonical_path: path.to_path_buf(),
        bytes: sources
            .get(path)
            .unwrap_or_else(|| panic!("source missing from immutable snapshot: {}", path.display()))
            .clone(),
        origin,
    });
    id
}

fn expand_node(
    graph: &mut SourceGraph,
    sources: &HashMap<PathBuf, String>,
    macros: &MacroDefinitions,
    from: SourceId,
    base_scope: &[String],
    ancestry: &[PathBuf],
    selected_sources: Option<&HashSet<PathBuf>>,
) {
    let node = graph.node(from).expect("new source node").clone();
    let records =
        super::source_edges::source_edge_records(&node.canonical_path, &node.bytes, macros, false);
    for record in records {
        if selected_sources.is_some_and(|sources| !sources.contains(&record.target)) {
            continue;
        }
        assert_eq!(
            record.from, node.canonical_path,
            "edge source identity drifted"
        );
        assert!(
            !ancestry.contains(&record.target),
            "recursive production source graph through {}",
            record.target.display()
        );
        let mut absolute_scope = base_scope.to_vec();
        absolute_scope.extend(record.from_module_scope);
        let inherited_origin = if node.origin == SourceOrigin::OpaqueMacroInclude {
            SourceOrigin::OpaqueMacroInclude
        } else {
            record.origin
        };
        let target = add_node(
            graph,
            sources,
            node.package,
            node.target,
            &record.target,
            inherited_origin,
        );
        let kind = match record.kind {
            SourceEdgeKind::Module { declared_name } => SourceEdgeKind::Module { declared_name },
            SourceEdgeKind::Include { .. } => SourceEdgeKind::Include {
                expansion_site: SyntaxId(
                    u32::try_from(graph.edges.len()).expect("edge count exceeds u32"),
                ),
            },
        };
        graph.edges.push(SourceEdge {
            from,
            from_module_scope: absolute_scope.clone(),
            target,
            kind: kind.clone(),
        });
        let child_scope = match kind {
            SourceEdgeKind::Module { declared_name } => {
                let mut scope = absolute_scope;
                scope.push(declared_name);
                scope
            }
            SourceEdgeKind::Include { .. } => absolute_scope,
        };
        let mut child_ancestry = ancestry.to_vec();
        child_ancestry.push(record.target);
        expand_node(
            graph,
            sources,
            macros,
            target,
            &child_scope,
            &child_ancestry,
            selected_sources,
        );
    }
}

use std::collections::HashSet;

use super::semantic_index::IndexError;
use super::semantic_index_build::Builder;
use super::source_model::{CrateUnit, ModuleId, PackageId, ScopeId, SourceId, TargetId};
use super::symbols::ModuleRecord;

pub(super) fn collect_modules(builder: &mut Builder<'_>) -> Result<(), IndexError> {
    let mut seen = HashSet::new();
    for unit in &builder.snapshot.graph.crates {
        add_module(builder, unit, unit.root, Vec::new(), None, &mut seen);
    }
    for edge in &builder.snapshot.graph.edges {
        let Some(node) = builder.snapshot.graph.node(edge.target) else {
            return Err(IndexError {
                source: Some(edge.from),
                reason: "source edge target is absent from snapshot".into(),
            });
        };
        let Some(unit) = builder
            .snapshot
            .graph
            .crates
            .iter()
            .find(|unit| unit.package == node.package && unit.target == node.target)
        else {
            return Err(IndexError {
                source: Some(edge.target),
                reason: "source node has no crate unit".into(),
            });
        };
        let mut path = edge.from_module_scope.clone();
        if matches!(
            edge.kind,
            super::source_model::SourceEdgeKind::Include { .. }
        ) && let Some(module) = builder
            .modules
            .iter()
            .find(|module| {
                module.package == unit.package
                    && module.target == unit.target
                    && module.path == path
            })
            .cloned()
        {
            builder.modules.push(ModuleRecord {
                source: edge.target,
                ..module
            });
            continue;
        }
        if let super::source_model::SourceEdgeKind::Module { declared_name } = &edge.kind {
            path.push(declared_name.clone());
        }
        let parent = scope_for_path(builder, unit.package, unit.target, &edge.from_module_scope);
        add_module(builder, unit, edge.target, path, parent, &mut seen);
    }
    Ok(())
}

fn add_module(
    builder: &mut Builder<'_>,
    unit: &CrateUnit,
    source: SourceId,
    path: Vec<String>,
    parent: Option<ScopeId>,
    seen: &mut HashSet<(PackageId, TargetId, SourceId, Vec<String>)>,
) {
    if !seen.insert((unit.package, unit.target, source, path.clone())) {
        return;
    }
    let ordinal = u32::try_from(builder.modules.len()).expect("module count exceeds u32");
    builder.modules.push(ModuleRecord {
        id: ModuleId(ordinal),
        package: unit.package,
        target: unit.target,
        scope: ScopeId(ordinal),
        source,
        path,
        parent,
        children: std::collections::BTreeMap::default(),
    });
}

fn scope_for_path(
    builder: &Builder<'_>,
    package: PackageId,
    target: TargetId,
    path: &[String],
) -> Option<ScopeId> {
    builder
        .modules
        .iter()
        .find(|module| module.package == package && module.target == target && module.path == path)
        .map(|module| module.scope)
}

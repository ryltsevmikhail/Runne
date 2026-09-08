use std::path::Path;

#[path = "guard/analyzer.rs"]
mod analyzer;
#[path = "guard/assignments.rs"]
mod assignments;
#[path = "guard/ast_deep_tests.rs"]
mod ast_deep_tests;
#[path = "guard/ast_tests.rs"]
mod ast_tests;
#[path = "guard/bodies.rs"]
mod bodies;
#[path = "guard/bodies_call_fallbacks.rs"]
mod bodies_call_fallbacks;
#[path = "guard/bodies_calls.rs"]
mod bodies_calls;
#[path = "guard/bodies_control.rs"]
mod bodies_control;
#[path = "guard/bodies_expr.rs"]
mod bodies_expr;
#[path = "guard/bodies_support.rs"]
mod bodies_support;
#[path = "guard/bodies_type_paths.rs"]
mod bodies_type_paths;
#[path = "guard/bodies_types.rs"]
mod bodies_types;
#[path = "guard/calls.rs"]
mod calls;
#[path = "guard/carrier_deep_tests.rs"]
mod carrier_deep_tests;
#[path = "guard/cfg_projection.rs"]
mod cfg_projection;
#[path = "guard/inventory_generated_provenance_tests.rs"]
mod inventory_generated_provenance_tests;
#[path = "guard/inventory_include_aliases.rs"]
mod inventory_include_aliases;
#[path = "guard/inventory_macro_bindings.rs"]
mod inventory_macro_bindings;
#[path = "guard/inventory_macro_collection.rs"]
mod inventory_macro_collection;
#[path = "guard/inventory_macro_resolution.rs"]
mod inventory_macro_resolution;
#[path = "guard/inventory_macro_rules.rs"]
mod inventory_macro_rules;
#[path = "guard/inventory_macro_scope.rs"]
mod inventory_macro_scope;
#[path = "guard/inventory_macro_semantic.rs"]
mod inventory_macro_semantic;
#[path = "guard/inventory_macro_tests.rs"]
mod inventory_macro_tests;
#[path = "guard/inventory_review_tests.rs"]
mod inventory_review_tests;
#[path = "guard/inventory_source_tokens.rs"]
mod inventory_source_tokens;
#[path = "guard/inventory_tests.rs"]
mod inventory_tests;
#[path = "guard/macro_semantics.rs"]
mod macro_semantics;
#[path = "guard/patterns.rs"]
mod patterns;
#[path = "guard/production_metadata.rs"]
mod production_metadata;
#[path = "guard/production_snapshot.rs"]
mod production_snapshot;
#[path = "guard/production_snapshot_targets.rs"]
mod production_snapshot_targets;
#[path = "guard/provenance.rs"]
mod provenance;
#[path = "guard/semantic_acceptance_support.rs"]
mod semantic_acceptance_support;
#[path = "guard/semantic_acceptance_tests.rs"]
mod semantic_acceptance_tests;
#[path = "guard/semantic_attribute_acceptance_tests.rs"]
mod semantic_attribute_acceptance_tests;
#[path = "guard/semantic_flow_tests.rs"]
mod semantic_flow_tests;
#[path = "guard/semantic_graph_acceptance_tests.rs"]
mod semantic_graph_acceptance_tests;
#[path = "guard/semantic_index.rs"]
mod semantic_index;
#[path = "guard/semantic_index_build.rs"]
mod semantic_index_build;
#[path = "guard/semantic_index_context.rs"]
mod semantic_index_context;
#[path = "guard/semantic_index_fixture.rs"]
mod semantic_index_fixture;
#[path = "guard/semantic_index_graph.rs"]
mod semantic_index_graph;
#[path = "guard/semantic_index_imports.rs"]
mod semantic_index_imports;
#[path = "guard/semantic_index_items.rs"]
mod semantic_index_items;
#[path = "guard/semantic_index_macro.rs"]
mod semantic_index_macro;
#[path = "guard/semantic_index_origin.rs"]
mod semantic_index_origin;
#[path = "guard/semantic_index_resolve.rs"]
mod semantic_index_resolve;
#[path = "guard/semantic_index_values.rs"]
mod semantic_index_values;
#[path = "guard/source_edge_macros.rs"]
mod source_edge_macros;
#[path = "guard/source_edge_paths.rs"]
mod source_edge_paths;
#[path = "guard/source_edges.rs"]
mod source_edges;
#[path = "guard/source_model.rs"]
mod source_model;
#[path = "guard/symbols.rs"]
mod symbols;
#[path = "guard/syntax.rs"]
mod syntax;

pub use calls::{assert_workspace_has_no_credential_service_calls, count_credential_service_calls};

pub(in crate::guard) struct ProductionSnapshot {
    pub(in crate::guard) graph: source_model::SourceGraph,
    pub(in crate::guard) macros: source_edge_macros::MacroDefinitions,
}

impl ProductionSnapshot {
    pub(in crate::guard) fn source_texts(&self) -> Vec<String> {
        let mut sources = self
            .graph
            .nodes
            .iter()
            .map(|node| (node.canonical_path.clone(), node.bytes.clone()))
            .collect::<Vec<_>>();
        sources.sort_by(|left, right| left.0.cmp(&right.0));
        sources.dedup_by(|left, right| left.0 == right.0);
        sources.into_iter().map(|(_, source)| source).collect()
    }
}

pub fn collect_workspace_production_sources(workspace: &Path, facade: &Path) -> Vec<String> {
    collect_workspace_production_snapshot(workspace, facade).source_texts()
}

pub(in crate::guard) fn collect_workspace_production_snapshot(
    workspace: &Path,
    facade: &Path,
) -> ProductionSnapshot {
    production_snapshot::collect(workspace, facade)
}

pub(in crate::guard) fn collect_workspace_credential_service_consumer_snapshot(
    workspace: &Path,
    facade: &Path,
) -> ProductionSnapshot {
    production_snapshot::collect_consumers(workspace, facade)
}

pub fn is_workspace_production_source(path: &Path, facade: &Path) -> bool {
    let _ = facade;
    path.extension()
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

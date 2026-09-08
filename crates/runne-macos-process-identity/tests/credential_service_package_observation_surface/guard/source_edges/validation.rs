use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{MacroDefinitions, source_edge_collection, source_edge_records};
use crate::guard::source_model::OpaqueSourceMacro;

pub(in crate::guard) fn validate_source_edges(
    path: &Path,
    source: &str,
    inventory: &HashSet<PathBuf>,
    definitions: &MacroDefinitions,
) -> Vec<OpaqueSourceMacro> {
    let collection = source_edge_collection(path, source, definitions, false);
    for target in collection.records.iter().map(|edge| &edge.target) {
        assert!(
            inventory.contains(target),
            "source edge escaped production inventory: {}",
            target.display()
        );
    }
    collection.opaque_source_macros
}

pub(in crate::guard) fn source_edges(
    path: &Path,
    source: &str,
    definitions: &MacroDefinitions,
    allow_unresolved: bool,
) -> Vec<PathBuf> {
    source_edge_records(path, source, definitions, allow_unresolved)
        .into_iter()
        .map(|edge| edge.target)
        .collect()
}

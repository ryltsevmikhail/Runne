use std::path::Path;

use super::super::source_edge_macros::MacroDefinitions;
use super::super::source_model::{OpaqueSourceMacro, SourceEdgeRecord};
use super::super::syntax::parse_source;
use super::SourceEdgeCollector;
use syn::visit::Visit;

pub(in crate::guard) struct SourceEdgeCollection {
    pub(super) records: Vec<SourceEdgeRecord>,
    pub(super) opaque_source_macros: Vec<OpaqueSourceMacro>,
}

pub(in crate::guard) fn source_edge_records(
    path: &Path,
    source: &str,
    definitions: &MacroDefinitions,
    allow_unresolved: bool,
) -> Vec<SourceEdgeRecord> {
    source_edge_collection(path, source, definitions, allow_unresolved).records
}

pub(in crate::guard) fn source_edge_collection(
    path: &Path,
    source: &str,
    definitions: &MacroDefinitions,
    _allow_unresolved: bool,
) -> SourceEdgeCollection {
    let file = parse_source(source);
    let mut records = Vec::new();
    let mut opaque_source_macros = Vec::new();
    SourceEdgeCollector {
        source: path,
        definitions,
        scope: Vec::new(),
        site_ordinal: 0,
        macro_position: 0,
        edges: &mut records,
        opaque_source_macros: &mut opaque_source_macros,
    }
    .visit_file(&file);
    SourceEdgeCollection {
        records,
        opaque_source_macros,
    }
}

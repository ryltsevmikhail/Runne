use std::path::PathBuf;

use super::ProductionSnapshot;
use super::semantic_index::{IndexError, SemanticIndex};
use super::source_model::{
    CrateUnit, PackageId, SourceGraph, SourceId, SourceNode, SourceOrigin, TargetId,
};

pub(super) fn from_source(source: &str) -> Result<SemanticIndex, IndexError> {
    let path = PathBuf::from("/__runne_guard_virtual__/src/lib.rs");
    let mut macros = super::source_edge_macros::MacroDefinitions::default();
    super::inventory_macro_scope::register_source_context(
        &mut macros,
        &path,
        &PathBuf::from("/__runne_guard_virtual__"),
        super::inventory_macro_resolution::MacroDependencyKind::Normal,
    );
    macros.extend(&path, source);
    let graph = SourceGraph {
        crates: vec![CrateUnit {
            package: PackageId(0),
            target: TargetId(0),
            crate_name: "runne_fixture".into(),
            root: SourceId(0),
        }],
        nodes: vec![SourceNode {
            id: SourceId(0),
            package: PackageId(0),
            target: TargetId(0),
            canonical_path: path,
            bytes: source.to_owned(),
            origin: SourceOrigin::RustModule,
        }],
        edges: Vec::new(),
        opaque_source_macros: Vec::new(),
    };
    super::semantic_index_build::build(&ProductionSnapshot { graph, macros })
}

pub(super) fn parse_source_fragment(source: &str) -> Result<syn::File, syn::Error> {
    match syn::parse_file(source) {
        Ok(file) => Ok(file),
        Err(original) => {
            for wrapped in [
                format!("fn __runne_guard_include() {{\n{source}\n}}"),
                format!("mod __runne_guard_include {{\n{source}\n}}"),
            ] {
                if let Ok(file) = syn::parse_file(&wrapped) {
                    return Ok(file);
                }
            }
            Err(original)
        }
    }
}

pub(super) fn effective_origin(source: &str, origin: SourceOrigin) -> SourceOrigin {
    if origin == SourceOrigin::ResolvedInclude && syn::parse_file(source).is_err() {
        SourceOrigin::ContextDependentInclude
    } else {
        origin
    }
}

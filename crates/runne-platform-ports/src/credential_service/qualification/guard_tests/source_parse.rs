use syn::File;

use super::{SourceUnit, metadata};

pub(super) struct ParsedSource {
    pub(super) unit: SourceUnit,
    pub(super) file: File,
    pub(super) bindings: Vec<metadata::Binding>,
    pub(super) impls: Vec<metadata::ImplRecord>,
    pub(super) supertraits: Vec<metadata::SupertraitRecord>,
    pub(super) aliases: Vec<metadata::AliasRecord>,
}

pub(super) fn parse_source(unit: &SourceUnit) -> Option<ParsedSource> {
    let file = syn::parse_file(&unit.source).ok()?;
    let mut bindings = Vec::new();
    let mut impls = Vec::new();
    let mut supertraits = Vec::new();
    let mut aliases = Vec::new();
    metadata::collect_metadata(
        &file.items,
        &mut bindings,
        &mut impls,
        &mut supertraits,
        &mut aliases,
    );
    Some(ParsedSource {
        unit: unit.clone(),
        file,
        bindings,
        impls,
        supertraits,
        aliases,
    })
}

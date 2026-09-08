use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

use super::super::semantic_index::SemanticIndex;
use super::super::source_edge_macros::{AttributeKind, AttributeResolution};
use super::super::source_model::{ScopeId, SourceId, SyntaxId};

#[path = "attribute_items.rs"]
mod items;
use items::{impl_item_attributes, item_attributes, trait_item_attributes};
#[path = "attribute_cfg.rs"]
mod cfg;
use cfg::condition_may_apply;

pub(super) fn analyze(index: &SemanticIndex) -> Vec<super::UnresolvedSite> {
    let mut unresolved = Vec::new();
    for indexed in &index.items {
        analyze_item(
            index,
            indexed.scope,
            indexed.source,
            indexed.syntax,
            &indexed.item,
            &mut unresolved,
        );
    }
    unresolved
}

pub(in super::super) fn item_has_opaque_attribute(
    index: &SemanticIndex,
    scope: ScopeId,
    item: &syn::Item,
) -> bool {
    let mut unresolved = Vec::new();
    analyze_item(
        index,
        scope,
        SourceId(u32::MAX),
        SyntaxId(u32::MAX),
        item,
        &mut unresolved,
    );
    !unresolved.is_empty()
}

fn analyze_item(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    item: &syn::Item,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    if !super::super::cfg_projection::is_production(item_attributes(item)) {
        return;
    }
    analyze_attributes(
        index,
        scope,
        source,
        syntax,
        item_attributes(item),
        unresolved,
    );
    match item {
        syn::Item::Fn(function) => {
            analyze_block_items(index, scope, source, syntax, &function.block, unresolved);
        }
        syn::Item::Impl(item_impl) => {
            for member in &item_impl.items {
                analyze_impl_item(index, scope, source, syntax, member, unresolved);
            }
        }
        syn::Item::Trait(item_trait) => {
            for member in &item_trait.items {
                analyze_trait_item(index, scope, source, syntax, member, unresolved);
            }
        }
        syn::Item::Mod(module) => {
            if let Some((_, items)) = &module.content {
                for item in items {
                    analyze_item(index, scope, source, syntax, item, unresolved);
                }
            }
        }
        _ => {}
    }
}

fn analyze_impl_item(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    item: &syn::ImplItem,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    let attrs = impl_item_attributes(item);
    if !super::super::cfg_projection::is_production(attrs) {
        return;
    }
    analyze_attributes(index, scope, source, syntax, attrs, unresolved);
    if let syn::ImplItem::Fn(function) = item {
        analyze_block_items(index, scope, source, syntax, &function.block, unresolved);
    }
}

fn analyze_trait_item(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    item: &syn::TraitItem,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    let attrs = trait_item_attributes(item);
    if !super::super::cfg_projection::is_production(attrs) {
        return;
    }
    analyze_attributes(index, scope, source, syntax, attrs, unresolved);
    if let syn::TraitItem::Fn(function) = item
        && let Some(block) = &function.default
    {
        analyze_block_items(index, scope, source, syntax, block, unresolved);
    }
}

fn analyze_block_items(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    block: &syn::Block,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    for statement in &block.stmts {
        if let syn::Stmt::Item(item) = statement {
            analyze_item(index, scope, source, syntax, item, unresolved);
        }
    }
}

fn analyze_attributes(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    attributes: &[Attribute],
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    for attribute in attributes {
        analyze_meta(index, scope, source, syntax, &attribute.meta, unresolved);
    }
}

fn analyze_meta(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    meta: &Meta,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    if meta.path().is_ident("cfg") || meta.path().is_ident("test") {
        return;
    }
    if let Meta::List(list) = meta {
        if list.path.is_ident("cfg_attr") {
            analyze_cfg_attr(index, scope, source, syntax, list, unresolved);
            return;
        }
        if list.path.is_ident("derive") {
            let paths = list
                .parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
                .unwrap_or_default();
            if paths.is_empty() {
                record_opaque(source, syntax, unresolved);
            }
            for path in paths {
                classify(
                    index,
                    scope,
                    source,
                    syntax,
                    &path,
                    AttributeKind::Derive,
                    unresolved,
                );
            }
            return;
        }
    }
    classify(
        index,
        scope,
        source,
        syntax,
        meta.path(),
        AttributeKind::Inert,
        unresolved,
    );
}

fn analyze_cfg_attr(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    list: &syn::MetaList,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    let Ok(parts) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        record_opaque(source, syntax, unresolved);
        return;
    };
    let Some(condition) = parts.first() else {
        record_opaque(source, syntax, unresolved);
        return;
    };
    if condition_may_apply(condition) {
        for applied in parts.iter().skip(1) {
            analyze_meta(index, scope, source, syntax, applied, unresolved);
        }
    }
}

fn classify(
    index: &SemanticIndex,
    scope: ScopeId,
    source: SourceId,
    syntax: SyntaxId,
    path: &syn::Path,
    kind: AttributeKind,
    unresolved: &mut Vec<super::UnresolvedSite>,
) {
    if matches!(
        index.classify_attribute(scope, path, kind),
        AttributeResolution::Opaque
    ) {
        record_opaque(source, syntax, unresolved);
    }
}

fn record_opaque(source: SourceId, syntax: SyntaxId, unresolved: &mut Vec<super::UnresolvedSite>) {
    unresolved.push(super::UnresolvedSite {
        source: Some(source),
        syntax: Some(syntax),
        reason: super::UnresolvedReason::UnsupportedMacro,
        detail: "production attribute expansion could not be proven".into(),
    });
}

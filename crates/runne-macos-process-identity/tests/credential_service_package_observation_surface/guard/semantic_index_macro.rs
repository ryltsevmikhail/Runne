use super::semantic_index::SemanticIndex;
use super::source_edge_macros::{
    AttributeKind, AttributeResolution, BuiltinAttribute, MacroResolution,
};
use super::source_model::ScopeId;

#[cfg(test)]
#[path = "semantic_index_macro/tests.rs"]
mod tests;

pub(super) fn classify_attribute(
    index: &SemanticIndex,
    scope: ScopeId,
    path: &syn::Path,
    kind: AttributeKind,
) -> AttributeResolution {
    let Some(name) = unqualified_name(path) else {
        return AttributeResolution::Opaque;
    };
    let builtin = match kind {
        AttributeKind::Inert if is_builtin_inert_attribute(&name) => BuiltinAttribute::Inert,
        AttributeKind::Derive if is_builtin_derive(&name) => BuiltinAttribute::Derive,
        _ => return AttributeResolution::Opaque,
    };
    if kind == AttributeKind::Derive && attribute_name_is_shadowed(index, scope, &name) {
        AttributeResolution::Opaque
    } else {
        AttributeResolution::Builtin(builtin)
    }
}

fn is_builtin_derive(name: &str) -> bool {
    matches!(
        name,
        "Clone" | "Copy" | "Debug" | "Default" | "Eq" | "Hash" | "Ord" | "PartialEq" | "PartialOrd"
    )
}

fn is_builtin_inert_attribute(name: &str) -> bool {
    matches!(
        name,
        "allow"
            | "alloc_error_handler"
            | "cfg"
            | "cfg_attr"
            | "cold"
            | "crate_name"
            | "crate_type"
            | "deny"
            | "deprecated"
            | "derive"
            | "doc"
            | "expect"
            | "export_name"
            | "feature"
            | "forbid"
            | "global_allocator"
            | "ignore"
            | "inline"
            | "link"
            | "link_name"
            | "link_section"
            | "macro_export"
            | "macro_use"
            | "must_use"
            | "no_main"
            | "no_implicit_prelude"
            | "no_mangle"
            | "no_std"
            | "non_exhaustive"
            | "panic_handler"
            | "path"
            | "proc_macro"
            | "proc_macro_attribute"
            | "proc_macro_derive"
            | "recursion_limit"
            | "repr"
            | "should_panic"
            | "target_feature"
            | "test"
            | "track_caller"
            | "type_length_limit"
            | "used"
            | "warn"
            | "windows_subsystem"
    )
}

pub(super) fn resolve_macro(
    index: &SemanticIndex,
    scope: ScopeId,
    invocation: &syn::Macro,
) -> MacroResolution {
    let Some(module) = index.modules.iter().find(|module| module.scope == scope) else {
        return MacroResolution::Unresolved(
            super::source_edge_macros::UnresolvedReason::MissingScope,
        );
    };
    let Some(source) = index.source_paths.get(&module.source) else {
        return MacroResolution::Unresolved(
            super::source_edge_macros::UnresolvedReason::MissingScope,
        );
    };
    let mut resolution =
        index
            .macros
            .resolve_invocation(source, &module.path, &invocation.path, &invocation.tokens);
    if matches!(resolution, MacroResolution::Unresolved(_))
        && let Some(external) = cross_crate_macro(index, scope, source, invocation)
    {
        resolution = external;
    }
    if matches!(resolution, MacroResolution::Builtin(_))
        && unqualified_name(&invocation.path)
            .is_none_or(|name| attribute_name_is_shadowed(index, scope, &name))
    {
        resolution = MacroResolution::External;
    }
    finalize(index, &mut resolution);
    resolution
}

pub(super) fn resolve_generated_macro(
    index: &SemanticIndex,
    parent: &super::source_edge_macros::ResolvedMacroInvocation,
    generated_items: &[syn::Item],
    invocation: &syn::Macro,
) -> MacroResolution {
    let mut resolution =
        index
            .macros
            .resolve_generated_invocation(parent, generated_items, invocation);
    finalize(index, &mut resolution);
    resolution
}

fn finalize(index: &SemanticIndex, resolution: &mut MacroResolution) {
    let MacroResolution::Workspace(resolved) = resolution else {
        return;
    };
    resolved.analysis_scope = definition_scope(index, resolved);
    let crate_tokens: proc_macro2::TokenStream =
        super::inventory_macro_semantic::DEFINITION_CRATE_MARKER
            .parse()
            .expect("definition crate marker token");
    for arm in &mut resolved.selected_arms {
        arm.bindings
            .push(super::inventory_macro_bindings::MacroArgumentBinding {
                name: "crate".into(),
                tokens: crate_tokens.clone(),
            });
    }
}

fn definition_scope(
    index: &SemanticIndex,
    resolved: &super::source_edge_macros::ResolvedMacroInvocation,
) -> Option<ScopeId> {
    index.modules.iter().find_map(|candidate| {
        let candidate_source = index.source_paths.get(&candidate.source)?;
        if candidate_source != &resolved.definition_source {
            return None;
        }
        let mut path = candidate.path.clone();
        path.extend(resolved.definition_scope.clone());
        index
            .modules
            .iter()
            .find(|module| {
                module.package == candidate.package
                    && module.target == candidate.target
                    && module.path == path
            })
            .map(|module| module.scope)
            .or(Some(candidate.scope))
    })
}

fn cross_crate_macro(
    index: &SemanticIndex,
    scope: ScopeId,
    source: &std::path::Path,
    invocation: &syn::Macro,
) -> Option<MacroResolution> {
    let invoked = invocation.path.segments.last()?.ident.to_string();
    let explicit = (invocation.path.segments.len() > 1).then(|| {
        (
            invocation.path.segments.first().unwrap().ident.to_string(),
            invoked.clone(),
        )
    });
    let imported = index
        .imports
        .iter()
        .find(|import| import.scope == scope && import.alias.as_deref() == Some(invoked.as_str()))
        .and_then(|import| Some((import.path.first()?.clone(), import.path.last()?.clone())));
    let (crate_name, exported_name) = explicit.or(imported)?;
    let definitions = super::inventory_macro_scope::dependency_exported_definitions(
        &index.macros,
        source,
        &crate_name,
        &exported_name,
    );
    let [definition] = definitions.as_slice() else {
        return Some(MacroResolution::Unresolved(
            super::source_edge_macros::UnresolvedReason::AmbiguousDefinition,
        ));
    };
    let module = index.module(scope)?;
    let invocation_position = super::inventory_macro_collection::invocation_position(
        &index.macros,
        source,
        &module.path,
        &invocation.path,
        &invocation.tokens,
    )?;
    Some(
        super::source_edge_macros::MacroDefinitions::resolve_known_definition(
            definition,
            &invocation.tokens,
            source,
            &module.path,
            invocation_position,
        ),
    )
}

fn unqualified_name(path: &syn::Path) -> Option<String> {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return None;
    }
    Some(path.segments.first()?.ident.to_string())
}

fn attribute_name_is_shadowed(index: &SemanticIndex, scope: ScopeId, name: &str) -> bool {
    let Some(module) = index.module(scope) else {
        return true;
    };
    let mut visible_scopes = vec![module.scope];
    let mut parent = module.parent;
    while let Some(scope) = parent {
        let Some(module) = index.module(scope) else {
            break;
        };
        visible_scopes.push(scope);
        parent = module.parent;
    }
    if index.imports.iter().any(|import| {
        visible_scopes.contains(&import.scope)
            && (import.glob || import.alias.as_deref() == Some(name))
    }) {
        return true;
    }
    if index.items.iter().any(|item| {
        visible_scopes.contains(&item.scope)
            && matches!(&item.item, syn::Item::ExternCrate(item) if item.attrs.iter().any(|attribute| attribute.path().is_ident("macro_use")))
    }) {
        return true;
    }
    let Some(source) = index.source_paths.get(&module.source) else {
        return true;
    };
    index
        .macros
        .items
        .get(name)
        .into_iter()
        .flatten()
        .any(|definition| {
            definition.source == *source && module.path.starts_with(&definition.scope)
        })
        || index
            .macros
            .aliases
            .get(name)
            .into_iter()
            .flatten()
            .any(|alias| alias.source == *source && module.path.starts_with(&alias.scope))
}

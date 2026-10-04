use std::path::Path;

use proc_macro2::TokenStream;
use syn::spanned::Spanned;

use super::macro_definitions::{self, Index};
use super::source_parse::ParsedSource;
use super::visitor::MacroDisposition;

#[derive(Clone, Copy)]
pub(super) struct MacroCall<'a> {
    pub(super) source: &'a ParsedSource,
    pub(super) parsed: &'a [ParsedSource],
    pub(super) local: &'a Index,
    pub(super) name: &'a str,
    pub(super) scope: &'a [String],
    pub(super) payload: Option<&'a TokenStream>,
    pub(super) call_position: usize,
    pub(super) disposition: MacroDisposition,
}

pub(super) fn relevance(call: MacroCall<'_>) -> Option<bool> {
    let MacroCall {
        source,
        parsed,
        local,
        name,
        scope,
        payload,
        call_position,
        disposition,
    } = call;
    if !matches!(
        disposition,
        MacroDisposition::ResolveLocal | MacroDisposition::ResolveContext
    ) || local.has_import(name, scope)
    {
        return None;
    }

    let mut latest = local
        .definition_resolution(name, scope, call_position, disposition, payload)
        .map(|(position, relevant)| ((position, 0), relevant));
    let definition_after_call = latest.is_none() && local.has_definition(name, scope);

    for item in &source.file.items {
        let syn::Item::Macro(include) = item else {
            continue;
        };
        if !super::super::edges::is_compiler_include(&include.mac.path)
            || super::item_is_test_only(super::item_attrs(item))
        {
            continue;
        }
        let include_position = super::macro_scope::position(include.mac.span());
        if include_position >= call_position {
            continue;
        }
        let conditional_include = has_conditional_attribute(&include.attrs);
        let Ok(literal) = syn::parse2::<syn::LitStr>(include.mac.tokens.clone()) else {
            if conditional_include {
                latest = taint_at(latest, include_position);
            }
            continue;
        };
        let path = source
            .unit
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(literal.value());
        let Some(included) = parsed
            .iter()
            .find(|candidate| candidate.unit.path == path && !candidate.unit.test_only)
        else {
            if conditional_include {
                latest = taint_at(latest, include_position);
            }
            continue;
        };
        let definitions =
            macro_definitions::index(&included.file.items, &included.unit.trusted_external_roots);
        let Some((definition_position, mut relevant)) =
            definitions.definition_resolution(name, scope, usize::MAX, disposition, payload)
        else {
            if conditional_include {
                latest = taint_at(latest, include_position);
            }
            continue;
        };
        relevant |= conditional_include;
        relevant |= definitions
            .definition_qualified_macro_paths(name, scope, usize::MAX)
            .into_iter()
            .any(|path| {
                qualified_path_is_untrusted(
                    source,
                    parsed,
                    &included.unit.trusted_external_roots,
                    &path,
                )
            });
        let key = (include_position, definition_position);
        if latest
            .as_ref()
            .is_none_or(|(latest_key, _)| key > *latest_key)
        {
            latest = Some((key, relevant));
        }
    }

    latest
        .map(|(_, relevant)| relevant)
        .or_else(|| definition_after_call.then_some(true))
}

fn taint_at(
    latest: Option<((usize, usize), bool)>,
    position: usize,
) -> Option<((usize, usize), bool)> {
    let key = (position, 0);
    if latest
        .as_ref()
        .is_none_or(|(latest_key, _)| key > *latest_key)
    {
        Some((key, true))
    } else {
        latest
    }
}

pub(super) fn qualified_path_is_untrusted(
    source: &ParsedSource,
    parsed: &[ParsedSource],
    trusted_roots: &std::collections::BTreeSet<String>,
    path: &str,
) -> bool {
    let Ok(path) = syn::parse_str::<syn::Path>(path) else {
        return true;
    };
    let Some(trusted) = super::macro_trust::trusted_external_path(&path) else {
        return true;
    };
    let root = trusted.split("::").next().unwrap_or_default();
    (!matches!(root, "core" | "std") && !trusted_roots.contains(root))
        || super::source_or_glob_shadows_root(source, parsed, root)
}

fn has_conditional_attribute(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

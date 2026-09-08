use std::path::{Path, PathBuf};

use super::inventory_macro_resolution::{
    MacroAlias, MacroDefinition, MacroDefinitions, MacroDependencyKind, MacroSourceContext,
};
use super::inventory_macro_rules::ArgumentTemplate;

pub(super) fn select_nearest_definition<'a>(
    candidates: &[&'a MacroDefinition],
    scope: &[String],
) -> &'a MacroDefinition {
    let depth = candidates
        .iter()
        .map(|candidate| candidate.scope.len())
        .max()
        .unwrap();
    let nearest = candidates
        .iter()
        .filter(|candidate| candidate.scope.len() == depth)
        .collect::<Vec<_>>();
    assert_eq!(
        nearest.len(),
        1,
        "ambiguous same-scope macro definition in {}",
        scope.join("::")
    );
    nearest[0]
}

pub(super) fn select_nearest_alias<'a>(candidates: &[&'a MacroAlias]) -> &'a MacroAlias {
    let depth = candidates
        .iter()
        .map(|candidate| candidate.scope.len())
        .max()
        .unwrap();
    let nearest = candidates
        .iter()
        .filter(|candidate| candidate.scope.len() == depth)
        .collect::<Vec<_>>();
    assert_eq!(nearest.len(), 1, "ambiguous same-scope macro alias");
    nearest[0]
}

pub(super) fn local_definitions<'a>(
    definitions: &'a MacroDefinitions,
    source: &Path,
    scope: &[String],
    name: &str,
    source_position: u32,
    exact_scope: bool,
) -> Vec<&'a MacroDefinition> {
    definitions
        .items
        .get(name)
        .into_iter()
        .flatten()
        .filter(|definition| {
            definition.source == source
                && definition.source_position < source_position
                && if exact_scope {
                    definition.scope == scope
                } else {
                    scope.starts_with(&definition.scope)
                }
        })
        .collect()
}

pub(super) fn local_aliases<'a>(
    definitions: &'a MacroDefinitions,
    source: &Path,
    scope: &[String],
    name: &str,
    source_position: u32,
    exact_scope: bool,
) -> Vec<&'a MacroAlias> {
    definitions
        .aliases
        .get(name)
        .into_iter()
        .flatten()
        .filter(|alias| {
            alias.source == source
                && alias.source_position < source_position
                && if exact_scope {
                    alias.scope == scope
                } else {
                    scope.starts_with(&alias.scope)
                }
        })
        .collect()
}

pub(super) fn nearby_external_definitions<'a>(
    definitions: &'a MacroDefinitions,
    source: &Path,
    name: &str,
) -> Vec<&'a MacroDefinition> {
    definitions
        .items
        .get(name)
        .into_iter()
        .flatten()
        .filter(|definition| {
            definition.source != source && same_crate_source(source, &definition.source)
        })
        .collect()
}

pub(super) fn register_dependency(
    definitions: &mut MacroDefinitions,
    consumer_root: &Path,
    kind: MacroDependencyKind,
    visible_name: &str,
    dependency_root: &Path,
) {
    let roots = definitions
        .dependencies
        .entry((
            consumer_root.to_path_buf(),
            kind,
            visible_name.replace('-', "_"),
        ))
        .or_default();
    if !roots.iter().any(|candidate| candidate == dependency_root) {
        roots.push(dependency_root.to_path_buf());
    }
}

pub(super) fn register_source_context(
    definitions: &mut MacroDefinitions,
    source: &Path,
    package_root: &Path,
    dependency_kind: MacroDependencyKind,
) {
    let context = MacroSourceContext {
        package_root: package_root.to_path_buf(),
        dependency_kind,
    };
    let contexts = definitions
        .source_contexts
        .entry(source.to_path_buf())
        .or_default();
    if !contexts.contains(&context) {
        contexts.push(context);
    }
}

pub(super) fn inherit_source_contexts(
    definitions: &mut MacroDefinitions,
    from: &Path,
    target: &Path,
) {
    let contexts = definitions
        .source_contexts
        .get(from)
        .cloned()
        .unwrap_or_default();
    for context in contexts {
        register_source_context(
            definitions,
            target,
            &context.package_root,
            context.dependency_kind,
        );
    }
}

pub(super) fn dependency_exported_definitions<'a>(
    definitions: &'a MacroDefinitions,
    source: &Path,
    visible_name: &str,
    name: &str,
) -> Vec<&'a MacroDefinition> {
    let roots = definitions
        .source_contexts
        .get(source)
        .into_iter()
        .flatten()
        .flat_map(|context| {
            definitions
                .dependencies
                .get(&(
                    context.package_root.clone(),
                    context.dependency_kind,
                    visible_name.to_owned(),
                ))
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    let mut matches = definitions
        .items
        .get(name)
        .into_iter()
        .flatten()
        .filter(|definition| {
            definition.exported
                && roots
                    .iter()
                    .any(|root| definition.source.starts_with(*root))
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|definition| definition.ordinal);
    matches.dedup_by_key(|definition| definition.ordinal);
    matches
}

pub(super) fn has_exact_local_symbol(
    definitions: &MacroDefinitions,
    source: &Path,
    scope: &[String],
    name: &str,
    source_position: u32,
) -> bool {
    !local_definitions(definitions, source, scope, name, source_position, true).is_empty()
        || !local_aliases(definitions, source, scope, name, source_position, true).is_empty()
}

pub(super) fn alias_target_scope(base: &[String], target: &[String]) -> (Vec<String>, String) {
    assert!(!target.is_empty(), "empty macro alias target");
    let mut scope = base.to_vec();
    let mut parts = target;
    if matches!(
        parts.first().map(String::as_str),
        Some("crate" | super::inventory_macro_semantic::DEFINITION_CRATE_MARKER)
    ) {
        scope.clear();
        parts = &parts[1..];
    } else if matches!(parts.first().map(String::as_str), Some("self")) {
        parts = &parts[1..];
    }
    scope.extend(parts[..parts.len() - 1].iter().cloned());
    (scope, parts.last().unwrap().clone())
}

pub(super) fn macro_path_scope(base: &[String], path: &syn::Path) -> Option<(Vec<String>, String)> {
    if path.leading_colon.is_some() || path.segments.is_empty() {
        return None;
    }
    let mut parts = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let name = parts.pop()?;
    let mut scope = base.to_vec();
    match parts.first().map(String::as_str) {
        Some("crate" | super::inventory_macro_semantic::DEFINITION_CRATE_MARKER) => {
            scope.clear();
            parts.remove(0);
        }
        Some("self") => {
            parts.remove(0);
        }
        Some("super") => {
            while parts.first().is_some_and(|part| part == "super") {
                scope.pop()?;
                parts.remove(0);
            }
        }
        _ => {}
    }
    scope.extend(parts);
    Some((scope, name))
}

pub(super) fn argument_tokens(argument: &ArgumentTemplate) -> proc_macro2::TokenStream {
    match argument {
        ArgumentTemplate::Empty => proc_macro2::TokenStream::new(),
        ArgumentTemplate::Literal(path) => format!("{path:?}")
            .parse()
            .unwrap_or_else(|error| panic!("cannot rebuild macro literal argument: {error}")),
        ArgumentTemplate::Forwarded | ArgumentTemplate::Unsupported(_) => {
            proc_macro2::TokenStream::new()
        }
    }
}

pub(super) fn same_crate_source(left: &Path, right: &Path) -> bool {
    source_root(left).is_some_and(|root| source_root(right).as_ref() == Some(&root))
}

fn source_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == "src"))
        .map(Path::to_path_buf)
}

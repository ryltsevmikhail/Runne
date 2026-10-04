use syn::Item;

use super::syntax::normalized_ident;
use super::visitor::MacroDisposition;

#[path = "macro_definition_collection.rs"]
mod macro_definition_collection;

pub(super) struct Index {
    definitions: Vec<Definition>,
    imports: Vec<Import>,
    shadowed_names: std::collections::BTreeSet<String>,
    local_modules: std::collections::BTreeSet<String>,
    trusted_external_roots: std::collections::BTreeSet<String>,
}

struct Definition {
    name: String,
    scope: Vec<String>,
    position: usize,
    tokens: proc_macro2::TokenStream,
    relevant: bool,
    context_relevant: bool,
    conditional: bool,
}

struct Import {
    name: String,
    root: Option<String>,
    scope: Vec<String>,
    glob: bool,
}

pub(super) fn index(
    items: &[Item],
    trusted_external_roots: &std::collections::BTreeSet<String>,
) -> Index {
    let mut index = Index {
        definitions: Vec::new(),
        imports: Vec::new(),
        shadowed_names: macro_definition_collection::all_macro_rule_names(items),
        local_modules: items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(item) => Some(normalized_ident(&item.ident)),
                _ => None,
            })
            .collect(),
        trusted_external_roots: trusted_external_roots.clone(),
    };
    macro_definition_collection::collect_items(items, &[], &mut index);
    macro_definition_collection::resolve_relevance(&mut index);
    index
}

pub(super) fn is_relevant(
    index: &Index,
    name: &str,
    disposition: MacroDisposition,
    scope: &[String],
    position: usize,
    payload: Option<&proc_macro2::TokenStream>,
) -> bool {
    let trusted_fallback = match disposition {
        MacroDisposition::OpaqueExternal | MacroDisposition::Direct => return true,
        MacroDisposition::Unrelated => return false,
        MacroDisposition::ResolveLocal | MacroDisposition::ResolveContext => false,
        MacroDisposition::ResolveTrusted => true,
    };
    index.definition_before(name, scope, position).map_or_else(
        || {
            !trusted_fallback
                && (index.has_import(name, scope)
                    || (!is_compiler_builtin_macro(name) && !index.has_definition(name, scope)))
        },
        |definition| {
            definition.relevant
                || (matches!(disposition, MacroDisposition::ResolveContext)
                    && is_compiler_builtin_macro(name)
                    && payload.is_some_and(|payload| {
                        super::macro_tokens::macro_invocation_forwards_qualification(
                            &definition.tokens,
                            payload,
                            &index.shadowed_builtins_at(&definition.scope, definition.position),
                        )
                    }))
                || payload.is_some_and(|payload| {
                    let shadowed =
                        index.shadowed_builtins_at(&definition.scope, definition.position);
                    super::macro_tokens::macro_invocation_has_dynamic_import(
                        &definition.tokens,
                        payload,
                        &shadowed,
                    )
                })
                || (matches!(disposition, MacroDisposition::ResolveContext)
                    && definition.context_relevant)
        },
    )
}

pub(super) fn is_compiler_builtin_macro(name: &str) -> bool {
    matches!(
        name,
        "assert"
            | "assert_eq"
            | "assert_ne"
            | "cfg"
            | "column"
            | "compile_error"
            | "concat"
            | "dbg"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "env"
            | "eprint"
            | "eprintln"
            | "file"
            | "format"
            | "format_args"
            | "include"
            | "include_bytes"
            | "include_str"
            | "line"
            | "matches"
            | "module_path"
            | "option_env"
            | "panic"
            | "print"
            | "println"
            | "stringify"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "vec"
            | "write"
            | "writeln"
    )
}

impl Index {
    pub(super) fn definition_resolution(
        &self,
        name: &str,
        scope: &[String],
        position: usize,
        disposition: MacroDisposition,
        payload: Option<&proc_macro2::TokenStream>,
    ) -> Option<(usize, bool)> {
        let definition = self.definition_before(name, scope, position)?;
        Some((
            definition.position,
            is_relevant(self, name, disposition, scope, position, payload),
        ))
    }

    pub(super) fn definition_qualified_macro_paths(
        &self,
        name: &str,
        scope: &[String],
        position: usize,
    ) -> std::collections::BTreeSet<String> {
        self.definition_before(name, scope, position)
            .map(|definition| super::macro_tokens::qualified_macro_paths(&definition.tokens))
            .unwrap_or_default()
    }

    fn shadowed_builtins_at(
        &self,
        scope: &[String],
        position: usize,
    ) -> std::collections::BTreeSet<String> {
        self.definitions
            .iter()
            .filter(|definition| {
                definition.position < position
                    && scope.starts_with(&definition.scope)
                    && is_compiler_builtin_macro(&definition.name)
            })
            .map(|definition| definition.name.clone())
            .chain(
                self.imports
                    .iter()
                    .filter(|import| {
                        scope.starts_with(&import.scope)
                            && is_compiler_builtin_macro(&import.name)
                            && !matches!(import.root.as_deref(), Some("std" | "core"))
                    })
                    .map(|import| import.name.clone()),
            )
            .collect()
    }

    pub(super) fn allows_trusted_fallback(&self, name: &str, scope: &[String]) -> bool {
        !self.has_untrusted_import(name, scope)
            && !self.has_definition(name, scope)
            && !self.shadowed_names.contains(name)
    }

    fn definition_before(
        &self,
        name: &str,
        scope: &[String],
        position: usize,
    ) -> Option<&Definition> {
        self.definitions
            .iter()
            .filter(|definition| {
                definition.name == name
                    && definition.position < position
                    && scope.starts_with(&definition.scope)
            })
            .max_by_key(|definition| (definition.scope.len(), definition.position))
    }

    pub(super) fn has_import(&self, name: &str, scope: &[String]) -> bool {
        self.imports.iter().any(|import| {
            (import.name == name || import.name == "*") && scope.starts_with(&import.scope)
        })
    }

    fn has_untrusted_import(&self, name: &str, scope: &[String]) -> bool {
        self.imports.iter().any(|import| {
            (import.name == name || import.name == "*")
                && scope.starts_with(&import.scope)
                && import.root.as_deref().is_none_or(|root| {
                    !(import.glob
                        && (self.local_modules.contains(root) || root.starts_with("runne_")))
                        && !matches!(root, "crate" | "self" | "super" | "std")
                        && super::macro_trust::trusted_bare_root(name) != Some(root)
                })
        })
    }

    fn has_untrusted_attribute_import(&self, name: &str, scope: &[String]) -> bool {
        let trusted_root = match name {
            "Serialize" | "Deserialize" => Some("serde"),
            "Error" => Some("thiserror"),
            "Clone" | "Copy" | "Debug" | "Default" | "Eq" | "Hash" | "Ord" | "PartialEq"
            | "PartialOrd" => Some("std"),
            _ => None,
        };
        self.imports.iter().any(|import| {
            (import.name == name || import.name == "*")
                && scope.starts_with(&import.scope)
                && import.root.as_deref() != trusted_root
        })
    }

    fn root_is_shadowed(&self, root: &str, scope: &[String]) -> bool {
        !matches!(root, "std" | "self" | "super" | "crate")
            && !self.trusted_external_roots.contains(root)
            || self.local_modules.contains(root)
            || self.imports.iter().any(|import| {
                import.name == root
                    && scope.starts_with(&import.scope)
                    && import.root.as_deref() != Some(root)
            })
    }

    pub(super) fn has_definition(&self, name: &str, scope: &[String]) -> bool {
        self.definitions
            .iter()
            .any(|definition| definition.name == name && scope.starts_with(&definition.scope))
    }
}

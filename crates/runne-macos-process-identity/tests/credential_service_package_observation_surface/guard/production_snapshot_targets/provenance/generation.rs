use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use syn::visit::{self, Visit};

#[path = "generation/local.rs"]
mod local;

pub(in crate::guard::production_snapshot_targets) fn possible<'a>(
    closure: &HashSet<PathBuf>,
    sources: &HashMap<PathBuf, String>,
    macros: &super::super::super::source_edge_macros::MacroDefinitions,
    dependencies: impl Iterator<Item = &'a String>,
) -> bool {
    let mut names = dependencies.cloned().collect::<HashSet<_>>();
    let mut glob = false;
    while closure
        .iter()
        .any(|path| imports(&sources[path], &mut names, &mut glob))
    {}
    closure.iter().any(|path| {
        let mut visitor = GeneratedSource {
            names: &names,
            glob,
            found: false,
        };
        visitor.visit_file(&super::super::super::syntax::parse_source(&sources[path]));
        visitor.found
    }) || local::possible(closure, macros, &names, glob)
}

fn imports(source: &str, names: &mut HashSet<String>, glob: &mut bool) -> bool {
    let mut visitor = Imports {
        names,
        glob,
        changed: false,
    };
    visitor.visit_file(&super::super::super::syntax::parse_source(source));
    visitor.changed
}

struct Imports<'a> {
    names: &'a mut HashSet<String>,
    glob: &'a mut bool,
    changed: bool,
}

impl<'ast> Visit<'ast> for Imports<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.changed |= import_tree(&node.tree, &mut Vec::new(), self.names, self.glob);
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        if self.names.contains(&node.ident.to_string()) {
            if let Some((_, alias)) = &node.rename {
                self.changed |= self.names.insert(alias.to_string());
            }
            self.changed |= node
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("macro_use"))
                && !std::mem::replace(self.glob, true);
        }
    }
}

fn import_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    names: &mut HashSet<String>,
    glob: &mut bool,
) -> bool {
    match tree {
        syn::UseTree::Path(path) => branch(&path.ident, prefix, |prefix| {
            import_tree(&path.tree, prefix, names, glob)
        }),
        syn::UseTree::Name(name) => binding(&name.ident, &name.ident, prefix, names),
        syn::UseTree::Rename(rename) => binding(&rename.ident, &rename.rename, prefix, names),
        syn::UseTree::Glob(_) => {
            let external = prefix.iter().any(|name| names.contains(name));
            let changed = external && !*glob;
            *glob |= external;
            changed
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| import_tree(tree, prefix, names, glob)),
    }
}

fn branch<F: FnOnce(&mut Vec<String>) -> bool>(
    name: &syn::Ident,
    prefix: &mut Vec<String>,
    visit: F,
) -> bool {
    prefix.push(name.to_string());
    let changed = visit(prefix);
    prefix.pop();
    changed
}

fn binding(
    original: &syn::Ident,
    alias: &syn::Ident,
    prefix: &mut Vec<String>,
    names: &mut HashSet<String>,
) -> bool {
    prefix.push(original.to_string());
    let external = prefix.iter().any(|name| names.contains(name));
    prefix.pop();
    external && names.insert(alias.to_string())
}

struct GeneratedSource<'a> {
    names: &'a HashSet<String>,
    glob: bool,
    found: bool,
}

impl<'ast> Visit<'ast> for GeneratedSource<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.found |= path_is_external(&node.path, self.names)
            || (self.glob && bare_macro_path(&node.path))
            || (node.path.is_ident("include") && include_is_generated(&node.tokens));
        visit::visit_macro(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        self.found |= path_is_external(node.path(), self.names)
            || (self.glob && bare_attribute_path(node.path()))
            || (node.path().is_ident("derive")
                && tokens_reference_external(&node.meta, self.names))
            || (node.path().is_ident("cfg_attr")
                && (self.glob || tokens_reference_external(&node.meta, self.names)));
        visit::visit_attribute(self, node);
    }
}

fn bare_macro_path(path: &syn::Path) -> bool {
    path.segments.len() == 1
        && !path.is_ident("include")
        && !path.is_ident("concat")
        && !path.is_ident("env")
}

fn bare_attribute_path(path: &syn::Path) -> bool {
    path.segments.len() == 1
        && ![
            "cfg", "cfg_attr", "derive", "allow", "deny", "warn", "path", "test",
        ]
        .iter()
        .any(|name| path.is_ident(name))
}

fn path_is_external(path: &syn::Path, names: &HashSet<String>) -> bool {
    path.segments
        .first()
        .is_some_and(|segment| names.contains(&segment.ident.to_string()))
}

fn include_is_generated(tokens: &proc_macro2::TokenStream) -> bool {
    syn::parse2::<syn::LitStr>(tokens.clone()).is_err()
}

fn tokens_reference_external(meta: &syn::Meta, names: &HashSet<String>) -> bool {
    let mut tokens = HashSet::new();
    if let syn::Meta::List(list) = meta {
        collect_names(list.tokens.clone(), &mut tokens);
    }
    tokens.iter().any(|token| names.contains(token))
}

fn collect_names(tokens: proc_macro2::TokenStream, names: &mut HashSet<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(ident) => {
                names.insert(ident.to_string());
            }
            proc_macro2::TokenTree::Group(group) => collect_names(group.stream(), names),
            proc_macro2::TokenTree::Literal(literal) => {
                if syn::parse_str::<syn::LitStr>(&literal.to_string())
                    .is_ok_and(|literal| literal.value() == "OUT_DIR")
                {
                    names.insert("OUT_DIR".to_owned());
                }
            }
            proc_macro2::TokenTree::Punct(_) => {}
        }
    }
}

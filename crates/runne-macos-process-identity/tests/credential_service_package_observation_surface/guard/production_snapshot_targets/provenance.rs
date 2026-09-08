use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use syn::visit::{self, Visit};

#[path = "provenance/generation.rs"]
pub(super) mod generation;

pub(super) fn references(
    closure: &HashSet<PathBuf>,
    sources: &HashMap<PathBuf, String>,
    dependency: &str,
    canonical_type: Option<&str>,
) -> bool {
    canonical_type.map_or_else(
        || {
            closure
                .iter()
                .any(|path| simple_reference(&sources[path], dependency))
        },
        |canonical_type| direct_reference(closure, sources, dependency, canonical_type),
    )
}

fn direct_reference(
    closure: &HashSet<PathBuf>,
    sources: &HashMap<PathBuf, String>,
    dependency: &str,
    canonical_type: &str,
) -> bool {
    let mut dependencies = HashSet::from([dependency.to_owned()]);
    let mut types = HashSet::from([canonical_type.to_owned()]);
    while closure.iter().any(|path| {
        imports(
            &sources[path],
            &mut dependencies,
            &mut types,
            canonical_type,
        )
    }) {}
    closure.iter().any(|path| {
        import_references(&sources[path], &dependencies, &types)
            || path_references(&sources[path], &dependencies, &types)
    })
}

fn path_references(source: &str, dependencies: &HashSet<String>, types: &HashSet<String>) -> bool {
    let mut visitor = DirectReference {
        dependencies,
        types,
        found: false,
    };
    visitor.visit_file(&super::super::syntax::parse_source(source));
    visitor.found
}

fn import_references(
    source: &str,
    dependencies: &HashSet<String>,
    types: &HashSet<String>,
) -> bool {
    super::super::syntax::parse_source(source)
        .items
        .iter()
        .any(|item| match item {
            syn::Item::Use(item) => {
                import_reference_tree(&item.tree, &mut Vec::new(), dependencies, types)
            }
            _ => false,
        })
}

fn import_reference_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    dependencies: &HashSet<String>,
    types: &HashSet<String>,
) -> bool {
    match tree {
        syn::UseTree::Path(path) => branch(&path.ident, prefix, |prefix| {
            import_reference_tree(&path.tree, prefix, dependencies, types)
        }),
        syn::UseTree::Name(name) => import_reference(&name.ident, prefix, dependencies, types),
        syn::UseTree::Rename(rename) => {
            import_reference(&rename.ident, prefix, dependencies, types)
        }
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| import_reference_tree(tree, prefix, dependencies, types)),
    }
}

fn import_reference(
    name: &syn::Ident,
    prefix: &mut Vec<String>,
    dependencies: &HashSet<String>,
    types: &HashSet<String>,
) -> bool {
    prefix.push(name.to_string());
    let found = prefix.iter().any(|name| dependencies.contains(name))
        && prefix.iter().any(|name| types.contains(name));
    prefix.pop();
    found
}

fn imports(
    source: &str,
    dependencies: &mut HashSet<String>,
    types: &mut HashSet<String>,
    canonical_type: &str,
) -> bool {
    let mut changed = false;
    for item in super::super::syntax::parse_source(source).items {
        match item {
            syn::Item::Use(item) => {
                changed |= import_tree(
                    &item.tree,
                    &mut Vec::new(),
                    dependencies,
                    types,
                    canonical_type,
                );
            }
            syn::Item::ExternCrate(item) => {
                if let Some((_, alias)) = item.rename {
                    changed |= dependencies.insert(alias.to_string());
                }
            }
            _ => {}
        }
    }
    changed
}

fn import_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    dependencies: &mut HashSet<String>,
    types: &mut HashSet<String>,
    canonical_type: &str,
) -> bool {
    match tree {
        syn::UseTree::Path(path) => branch(&path.ident, prefix, |prefix| {
            import_tree(&path.tree, prefix, dependencies, types, canonical_type)
        }),
        syn::UseTree::Name(name) => binding(
            &name.ident,
            &name.ident,
            prefix,
            dependencies,
            types,
            canonical_type,
        ),
        syn::UseTree::Rename(rename) => binding(
            &rename.ident,
            &rename.rename,
            prefix,
            dependencies,
            types,
            canonical_type,
        ),
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| import_tree(tree, prefix, dependencies, types, canonical_type)),
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
    dependencies: &mut HashSet<String>,
    types: &mut HashSet<String>,
    canonical_type: &str,
) -> bool {
    prefix.push(original.to_string());
    let references_dependency = prefix.iter().any(|name| dependencies.contains(name));
    let references_type = prefix.iter().any(|name| name == canonical_type);
    prefix.pop();
    if !references_dependency {
        return false;
    }
    let mut changed = dependencies.insert(alias.to_string());
    if references_type {
        changed |= types.insert(alias.to_string());
    }
    changed
}

struct DirectReference<'a> {
    dependencies: &'a HashSet<String>,
    types: &'a HashSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for DirectReference<'_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.found |= path
            .segments
            .iter()
            .any(|segment| self.dependencies.contains(&segment.ident.to_string()))
            && path
                .segments
                .iter()
                .any(|segment| self.types.contains(&segment.ident.to_string()));
        visit::visit_path(self, path);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        self.found |= macro_tokens_reference(&node.mac.tokens, self.dependencies, self.types);
    }
}

fn macro_tokens_reference(
    tokens: &proc_macro2::TokenStream,
    dependencies: &HashSet<String>,
    types: &HashSet<String>,
) -> bool {
    let mut names = HashSet::new();
    collect_token_names(tokens.clone(), &mut names);
    names.iter().any(|name| dependencies.contains(name))
        && names.iter().any(|name| types.contains(name))
}

fn collect_token_names(tokens: proc_macro2::TokenStream, names: &mut HashSet<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(ident) => {
                names.insert(ident.to_string());
            }
            proc_macro2::TokenTree::Group(group) => collect_token_names(group.stream(), names),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
}

fn simple_reference(source: &str, dependency: &str) -> bool {
    let mut visitor = SimpleReference {
        dependency,
        found: false,
    };
    visitor.visit_file(&super::super::syntax::parse_source(source));
    visitor.found
}

struct SimpleReference<'a> {
    dependency: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for SimpleReference<'_> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.found |= use_tree_references(&node.tree, self.dependency);
        visit::visit_item_use(self, node);
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        self.found |= node.ident == self.dependency;
        visit::visit_item_extern_crate(self, node);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.found |= path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == self.dependency);
        visit::visit_path(self, path);
    }
}

fn use_tree_references(tree: &syn::UseTree, dependency: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => path.ident == dependency,
        syn::UseTree::Name(name) => name.ident == dependency,
        syn::UseTree::Rename(rename) => rename.ident == dependency,
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_references(item, dependency)),
    }
}

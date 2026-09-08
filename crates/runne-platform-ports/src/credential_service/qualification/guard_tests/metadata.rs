use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Item, ItemUse, Type, UseTree};

use super::{item_attrs, item_is_test_only};

pub(super) struct Binding {
    pub(super) local: Option<String>,
    pub(super) target: String,
    pub(super) public: bool,
}

pub(super) struct ImplRecord {
    pub(super) trait_name: Option<String>,
    pub(super) self_name: Option<String>,
}

pub(super) struct SupertraitRecord {
    pub(super) name: String,
    pub(super) bases: Vec<String>,
}

pub(super) struct AliasRecord {
    pub(super) name: String,
    pub(super) bases: Vec<String>,
    pub(super) has_qualified_path: bool,
    pub(super) qualified_modules: Vec<String>,
}

pub(super) fn collect_metadata(
    items: &[Item],
    bindings: &mut Vec<Binding>,
    impls: &mut Vec<ImplRecord>,
    supertraits: &mut Vec<SupertraitRecord>,
    aliases: &mut Vec<AliasRecord>,
) {
    for item in items {
        if item_is_test_only(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Use(item) => collect_use(item, bindings),
            Item::Impl(item) => impls.push(ImplRecord {
                trait_name: item
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| last_path_segment(path)),
                self_name: type_name(&item.self_ty),
            }),
            Item::Trait(item) => supertraits.push(SupertraitRecord {
                name: item.ident.to_string(),
                bases: item
                    .supertraits
                    .iter()
                    .filter_map(|bound| match bound {
                        syn::TypeParamBound::Trait(bound) => last_path_segment(&bound.path),
                        _ => None,
                    })
                    .collect(),
            }),
            Item::Type(item) => {
                let (bases, has_qualified_path, qualified_modules) = type_bases(&item.ty);
                aliases.push(AliasRecord {
                    name: item.ident.to_string(),
                    bases,
                    has_qualified_path,
                    qualified_modules,
                });
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_metadata(nested, bindings, impls, supertraits, aliases);
                }
            }
            _ => {}
        }
    }
}

fn collect_use(item: &ItemUse, bindings: &mut Vec<Binding>) {
    collect_use_tree(
        &item.tree,
        "",
        matches!(item.vis, syn::Visibility::Public(_)),
        bindings,
    );
}

fn collect_use_tree(tree: &UseTree, prefix: &str, public: bool, bindings: &mut Vec<Binding>) {
    match tree {
        UseTree::Path(path) => {
            let next_prefix = join_path(prefix, &path.ident.to_string());
            collect_use_tree(&path.tree, &next_prefix, public, bindings);
        }
        UseTree::Name(name) => bindings.push(Binding {
            local: Some(name.ident.to_string()),
            target: join_path(prefix, &name.ident.to_string()),
            public,
        }),
        UseTree::Rename(rename) => bindings.push(Binding {
            local: Some(rename.rename.to_string()),
            target: join_path(prefix, &rename.ident.to_string()),
            public,
        }),
        UseTree::Glob(_) => bindings.push(Binding {
            local: None,
            target: join_path(prefix, "*"),
            public,
        }),
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree(tree, prefix, public, bindings);
            }
        }
    }
}

pub(super) fn is_known_target(target: &str, known: &BTreeSet<String>) -> bool {
    target
        .rsplit("::")
        .next()
        .is_some_and(|segment| segment != "*" && known.contains(segment))
}

pub(super) fn alias_has_local_provenance(
    alias: &AliasRecord,
    aliases: &[AliasRecord],
    bindings: &[Binding],
    impls: &[ImplRecord],
    qualification_names: &BTreeSet<String>,
    implementers: &BTreeSet<String>,
) -> bool {
    impls.iter().any(|item| {
        item.self_name
            .as_ref()
            .is_some_and(|name| alias.bases.contains(name))
            && item
                .trait_name
                .as_ref()
                .is_some_and(|name| qualification_names.contains(name))
    }) || bindings.iter().any(|binding| {
        binding
            .local
            .as_ref()
            .is_some_and(|name| alias.bases.contains(name))
            && is_known_target(&binding.target, implementers)
    }) || aliases.iter().any(|local| {
        local.name != alias.name
            && implementers.contains(&local.name)
            && alias.bases.contains(&local.name)
    })
}

pub(super) fn last_path_segment(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

pub(super) fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn type_bases(ty: &Type) -> (Vec<String>, bool, Vec<String>) {
    let mut visitor = TypeBases::default();
    visitor.visit_type(ty);
    (
        visitor.bases,
        visitor.has_qualified_path,
        visitor.qualified_modules,
    )
}

#[derive(Default)]
struct TypeBases {
    bases: Vec<String>,
    has_qualified_path: bool,
    qualified_modules: Vec<String>,
}

impl TypeBases {
    fn push(&mut self, name: String) {
        if !self.bases.contains(&name) {
            self.bases.push(name);
        }
    }

    fn push_tokens(&mut self, tokens: &TokenStream) {
        for token in tokens.clone() {
            match token {
                TokenTree::Ident(identifier) => self.push(identifier.to_string()),
                TokenTree::Group(group) => self.push_tokens(&group.stream()),
                TokenTree::Literal(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for TypeBases {
    fn visit_type(&mut self, ty: &'ast Type) {
        if let Type::Verbatim(tokens) = ty {
            self.push_tokens(tokens);
        } else {
            visit::visit_type(self, ty);
        }
    }

    fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
        self.has_qualified_path |= ty.path.segments.len() > 1;
        if ty.path.segments.len() > 1 {
            let index = ty.path.segments.len() - 2;
            self.push_module(ty.path.segments[index].ident.to_string());
        }
        if let Some(name) = last_path_segment(&ty.path) {
            self.push(name);
        }
        visit::visit_type_path(self, ty);
    }

    fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
        if let Some(name) = last_path_segment(&bound.path) {
            self.push(name);
        }
        visit::visit_trait_bound(self, bound);
    }

    fn visit_type_macro(&mut self, ty: &'ast syn::TypeMacro) {
        self.push_tokens(&ty.mac.tokens);
        visit::visit_type_macro(self, ty);
    }
}

impl TypeBases {
    fn push_module(&mut self, name: String) {
        if !matches!(name.as_str(), "crate" | "self" | "super")
            && !self.qualified_modules.contains(&name)
        {
            self.qualified_modules.push(name);
        }
    }
}

fn join_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}::{segment}")
    }
}

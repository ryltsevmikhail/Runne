use std::collections::BTreeSet;

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

pub(super) fn collect_metadata(
    items: &[Item],
    bindings: &mut Vec<Binding>,
    impls: &mut Vec<ImplRecord>,
    supertraits: &mut Vec<SupertraitRecord>,
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
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_metadata(nested, bindings, impls, supertraits);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn qualification_names_with_supertraits<'a>(
    names: &BTreeSet<String>,
    records: impl Iterator<Item = &'a SupertraitRecord>,
) -> BTreeSet<String> {
    let records: Vec<_> = records.collect();
    let mut known = names.clone();
    loop {
        let previous = known.len();
        for record in &records {
            if record.bases.iter().any(|base| known.contains(base)) {
                known.insert(record.name.clone());
            }
        }
        if known.len() == previous {
            return known;
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

fn join_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}::{segment}")
    }
}

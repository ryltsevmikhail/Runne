pub(super) fn trusted_external_path(path: &syn::Path) -> Option<String> {
    if path.segments.len() < 2 {
        return None;
    }
    let joined = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    matches!(
        joined.as_str(),
        "core::stringify"
            | "anyhow::bail"
            | "async_stream::stream"
            | "log::error"
            | "log::info"
            | "rusqlite::params"
            | "rustix::cmsg_space"
            | "serde_json::json"
            | "static_assertions::assert_not_impl_any"
            | "std::include"
            | "std::matches"
            | "std::stringify"
            | "std::mem::offset_of"
            | "std::ptr::addr_of_mut"
            | "std::thread_local"
            | "tauri::generate_context"
            | "tauri::generate_handler"
            | "tauri::include_image"
            | "tauri::command"
            | "tokio::join"
            | "tokio::pin"
            | "tokio::select"
            | "tokio::test"
            | "tracing::error"
            | "tracing::info"
            | "tracing::warn"
    )
    .then_some(joined)
}

pub fn source_shadows_root(file: &syn::File, root: &str) -> bool {
    let items = macro_trust_inventory::production_items(file);
    let local_modules = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(item) => Some(item.ident.to_string()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    items.iter().any(|item| match item {
        syn::Item::Mod(item) => item.ident == root,
        syn::Item::Use(item) => use_tree_shadows(&item.tree, root, &local_modules, None),
        syn::Item::ExternCrate(item) => item
            .rename
            .as_ref()
            .is_some_and(|(_, rename)| rename == root && item.ident != root),
        _ => false,
    })
}

pub(super) fn source_shadows_symbol(file: &syn::File, symbol: &str, root: &str) -> bool {
    let items = macro_trust_inventory::production_items(file);
    let local_modules = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(item) => Some(item.ident.to_string()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    items.iter().any(|item| {
        let syn::Item::Use(item) = item else {
            return false;
        };
        use_tree_binds_symbol(&item.tree, symbol, root, &local_modules, None)
    })
}

pub(super) fn trusted_bare_root(name: &str) -> Option<&'static str> {
    match name {
        "json" => Some("serde_json"),
        "params" => Some("rusqlite"),
        "define_class" | "extern_protocol" | "msg_send" => Some("objc2"),
        "offset_of" | "thread_local" => Some("std"),
        _ => None,
    }
}

pub(super) fn has_macro_use(file: &syn::File) -> bool {
    file.items.iter().any(|item| match item {
        syn::Item::ExternCrate(item) => item.attrs.iter().any(is_macro_use),
        syn::Item::Mod(item) => item.attrs.iter().any(is_macro_use),
        _ => false,
    })
}

pub(super) fn trusted_local_macro_import(file: &syn::File, name: &str) -> bool {
    name == "uuid_v7_newtype"
        && file.items.iter().any(|item| match item {
            syn::Item::Use(item) => use_tree_has_path(
                &item.tree,
                &["crate", "id", "uuid_v7_newtype"],
                &mut Vec::new(),
            ),
            _ => false,
        })
}

fn use_tree_has_path(tree: &syn::UseTree, expected: &[&str], prefix: &mut Vec<String>) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            let found = use_tree_has_path(&path.tree, expected, prefix);
            prefix.pop();
            found
        }
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            let found = prefix
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied());
            prefix.pop();
            found
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_has_path(tree, expected, prefix)),
        syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => false,
    }
}

fn is_macro_use(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("macro_use")
}

fn use_tree_shadows(
    tree: &syn::UseTree,
    root: &str,
    local_modules: &std::collections::BTreeSet<String>,
    first: Option<String>,
) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_shadows(
            &path.tree,
            root,
            local_modules,
            first.or_else(|| Some(path.ident.to_string())),
        ),
        syn::UseTree::Name(name) => {
            name.ident == root && first.as_deref().is_some_and(|head| head != root)
        }
        syn::UseTree::Rename(rename) => {
            let original = rename.ident.to_string();
            let head = first.as_deref().unwrap_or(&original);
            rename.rename == root && head != root
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_shadows(tree, root, local_modules, first.clone())),
        syn::UseTree::Glob(_) => first
            .as_deref()
            .is_some_and(|head| is_external_head(head, root, local_modules)),
    }
}

pub(super) fn local_glob_modules(file: &syn::File) -> std::collections::BTreeSet<String> {
    fn collect(
        tree: &syn::UseTree,
        path: &mut Vec<String>,
        names: &mut std::collections::BTreeSet<String>,
    ) {
        match tree {
            syn::UseTree::Path(segment) => {
                path.push(segment.ident.to_string());
                collect(&segment.tree, path, names);
                path.pop();
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    collect(tree, path, names);
                }
            }
            syn::UseTree::Glob(_) => {
                let module = path
                    .iter()
                    .rev()
                    .find(|segment| !matches!(segment.as_str(), "crate" | "self" | "super"))
                    .cloned()
                    .unwrap_or_else(|| "*".to_owned());
                names.insert(module);
            }
            _ => {}
        }
    }
    let mut names = std::collections::BTreeSet::new();
    for item in macro_trust_inventory::production_items(file) {
        if let syn::Item::Use(item) = item {
            collect(&item.tree, &mut Vec::new(), &mut names);
        }
    }
    names
}

fn use_tree_binds_symbol(
    tree: &syn::UseTree,
    symbol: &str,
    root: &str,
    local_modules: &std::collections::BTreeSet<String>,
    first: Option<String>,
) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_binds_symbol(
            &path.tree,
            symbol,
            root,
            local_modules,
            first.or_else(|| Some(path.ident.to_string())),
        ),
        syn::UseTree::Name(name) => {
            name.ident == symbol
                && first
                    .as_deref()
                    .is_some_and(|head| is_external_head(head, root, local_modules))
        }
        syn::UseTree::Rename(rename) => {
            rename.rename == symbol
                && first
                    .as_deref()
                    .is_some_and(|head| is_external_head(head, root, local_modules))
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_binds_symbol(tree, symbol, root, local_modules, first.clone())),
        syn::UseTree::Glob(_) => false,
    }
}

fn is_external_head(
    head: &str,
    root: &str,
    local_modules: &std::collections::BTreeSet<String>,
) -> bool {
    !matches!(head, "crate" | "self" | "super")
        && head != root
        && !head.starts_with("runne_")
        && !local_modules.contains(head)
}

#[cfg(test)]
#[path = "macro_import_trust_tests.rs"]
mod macro_import_trust_tests;
#[path = "macro_trust_inventory.rs"]
mod macro_trust_inventory;

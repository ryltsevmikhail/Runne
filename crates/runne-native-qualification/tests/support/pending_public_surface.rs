use std::collections::BTreeSet;

use syn::{ImplItem, Item, Type, UseTree, Visibility};

use crate::pending_surface_aliases::{Alias, ident_name, type_name};
use crate::pending_surface_allowlist::{
    exact_admission_impl, exact_admission_reexport, exact_admission_struct, exact_reexport,
    exact_relay_decode,
};
use crate::pending_surface_types::{
    foreign_mod_contains, path_contains, signature_contains, trait_alias_contains, trait_contains,
    type_contains,
};

const PENDING: &str = "PendingQualificationFault";

pub fn audit_public_surface(
    files: &[(String, syn::File)],
    family: &BTreeSet<String>,
    aliases: &[Alias],
) -> Vec<String> {
    let symbols = expand_symbols(files, family, aliases);
    let mut audit = PublicAudit::default();
    for (source, file) in files {
        audit_items(&file.items, source, 0, family, &symbols, &mut audit);
    }
    audit.finish()
}

#[derive(Default)]
struct PublicAudit {
    pending_module: usize,
    pending_reexport: usize,
    relay_decode: usize,
    violations: Vec<String>,
}

impl PublicAudit {
    fn finish(mut self) -> Vec<String> {
        for (observed, label) in [
            (self.pending_module, "private pending module declaration"),
            (self.pending_reexport, "exact pending public re-export"),
            (self.relay_decode, "exact relay decode boundary"),
        ] {
            if observed != 1 {
                self.violations
                    .push(format!("expected one {label}, found {observed}"));
            }
        }
        self.violations
    }
}

fn expand_symbols(
    files: &[(String, syn::File)],
    family: &BTreeSet<String>,
    aliases: &[Alias],
) -> BTreeSet<String> {
    let mut symbols = family.clone();
    loop {
        let before = symbols.len();
        for alias in aliases {
            if symbols.contains(&alias.left) || symbols.contains(&alias.right) {
                symbols.insert(alias.left.clone());
                symbols.insert(alias.right.clone());
            }
        }
        for (_, file) in files {
            collect_tainted_symbols(&file.items, family, &mut symbols);
        }
        if symbols.len() == before {
            return symbols;
        }
    }
}

fn collect_tainted_symbols(
    items: &[Item],
    family: &BTreeSet<String>,
    symbols: &mut BTreeSet<String>,
) {
    for item in items {
        match item {
            Item::Fn(item) if signature_contains(&item.sig, family) => {
                symbols.insert(ident_name(&item.sig.ident));
            }
            Item::Const(item) if type_contains(&item.ty, family) => {
                symbols.insert(ident_name(&item.ident));
            }
            Item::Static(item) if type_contains(&item.ty, family) => {
                symbols.insert(ident_name(&item.ident));
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_tainted_symbols(nested, family, symbols);
                }
            }
            _ => {}
        }
    }
}

fn audit_items(
    items: &[Item],
    source: &str,
    depth: usize,
    family: &BTreeSet<String>,
    symbols: &BTreeSet<String>,
    audit: &mut PublicAudit,
) {
    for item in items {
        match item {
            Item::Fn(item) if is_visible(&item.vis) && signature_contains(&item.sig, family) => {
                audit.violations.push(format!(
                    "{source}: visible free function carries pending state"
                ));
            }
            Item::Struct(item)
                if is_visible(&item.vis)
                    && ident_name(&item.ident) != PENDING
                    && family.contains(&ident_name(&item.ident)) =>
            {
                if !exact_admission_struct(item, source) {
                    audit
                        .violations
                        .push(format!("{source}: visible struct wraps pending state"));
                }
            }
            Item::Enum(item)
                if is_visible(&item.vis) && family.contains(&ident_name(&item.ident)) =>
            {
                audit
                    .violations
                    .push(format!("{source}: visible enum wraps pending state"));
            }
            Item::Union(item)
                if is_visible(&item.vis) && family.contains(&ident_name(&item.ident)) =>
            {
                audit
                    .violations
                    .push(format!("{source}: visible union wraps pending state"));
            }
            Item::Type(item) if type_contains(&item.ty, family) => {
                audit
                    .violations
                    .push(format!("{source}: type alias carries pending state"));
            }
            Item::Const(item) if is_visible(&item.vis) && type_contains(&item.ty, family) => audit
                .violations
                .push(format!("{source}: visible const carries pending state")),
            Item::Static(item) if is_visible(&item.vis) && type_contains(&item.ty, family) => audit
                .violations
                .push(format!("{source}: visible static carries pending state")),
            Item::Trait(item) if is_visible(&item.vis) && trait_contains(item, family) => {
                audit
                    .violations
                    .push(format!("{source}: visible trait carries pending state"));
            }
            Item::TraitAlias(item)
                if is_visible(&item.vis) && trait_alias_contains(item, family) =>
            {
                audit.violations.push(format!(
                    "{source}: visible trait alias carries pending state"
                ));
            }
            Item::ForeignMod(item) if foreign_mod_contains(item, family) => {
                audit
                    .violations
                    .push(format!("{source}: foreign module carries pending state"));
            }
            Item::Use(item) if is_visible(&item.vis) => {
                if depth == 0 && exact_reexport(item, source) {
                    audit.pending_reexport += 1;
                } else if depth == 0 && exact_admission_reexport(item, source) {
                } else if use_mentions(&item.tree, symbols) {
                    audit
                        .violations
                        .push(format!("{source}: visible re-export carries pending state"));
                }
            }
            Item::Mod(item) => {
                if ident_name(&item.ident) == "pending" {
                    if source == "lib.rs"
                        && depth == 0
                        && matches!(item.vis, Visibility::Inherited)
                        && item.attrs.is_empty()
                        && item.content.is_none()
                    {
                        audit.pending_module += 1;
                    } else {
                        audit
                            .violations
                            .push(format!("{source}: pending module is not exact and private"));
                    }
                }
                if let Some((_, nested)) = &item.content {
                    audit_items(nested, source, depth + 1, family, symbols, audit);
                }
            }
            Item::Impl(item) => audit_impl(item, source, depth, family, audit),
            _ => {}
        }
    }
}

fn audit_impl(
    item: &syn::ItemImpl,
    source: &str,
    depth: usize,
    family: &BTreeSet<String>,
    audit: &mut PublicAudit,
) {
    let trait_contains_pending = item
        .trait_
        .as_ref()
        .is_some_and(|(_, path, _)| path_contains(path, family));
    if type_contains(&item.self_ty, family) || trait_contains_pending {
        if depth == 0 && exact_admission_impl(item, source) {
            return;
        }
        let direct_pending = type_name(&item.self_ty).is_some_and(|(name, _)| name == PENDING)
            && matches!(&*item.self_ty, Type::Path(path) if path.path.segments.len() == 1);
        if !(source == "pending.rs" && direct_pending && item.trait_.is_none()) {
            audit
                .violations
                .push(format!("{source}: impl target contains pending state"));
        }
        return;
    }
    for member in &item.items {
        match member {
            ImplItem::Fn(method) if signature_contains(&method.sig, family) => {
                if depth == 0 && exact_relay_decode(item, method, source) {
                    audit.relay_decode += 1;
                } else {
                    audit.violations.push(format!(
                        "{source}: associated function carries pending state"
                    ));
                }
            }
            ImplItem::Const(item) if type_contains(&item.ty, family) => {
                audit
                    .violations
                    .push(format!("{source}: associated const carries pending state"));
            }
            ImplItem::Type(item) if type_contains(&item.ty, family) => {
                audit
                    .violations
                    .push(format!("{source}: associated type carries pending state"));
            }
            ImplItem::Macro(_) | ImplItem::Verbatim(_) => audit
                .violations
                .push(format!("{source}: unexpanded associated item is forbidden")),
            _ => {}
        }
    }
}

fn use_mentions(tree: &UseTree, symbols: &BTreeSet<String>) -> bool {
    match tree {
        UseTree::Path(path) => {
            symbols.contains(&ident_name(&path.ident)) || use_mentions(&path.tree, symbols)
        }
        UseTree::Name(name) => symbols.contains(&ident_name(&name.ident)),
        UseTree::Rename(rename) => {
            symbols.contains(&ident_name(&rename.ident))
                || symbols.contains(&ident_name(&rename.rename))
        }
        UseTree::Group(group) => group.items.iter().any(|item| use_mentions(item, symbols)),
        UseTree::Glob(_) => true,
    }
}

const fn is_visible(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

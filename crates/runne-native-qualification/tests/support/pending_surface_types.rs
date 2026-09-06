use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{Item, Type};

use crate::pending_surface_aliases::{Alias, ident_name};

pub fn expand_family(
    files: &[(String, syn::File)],
    aliases: &[Alias],
    seed: &str,
) -> BTreeSet<String> {
    let mut family = BTreeSet::from([seed.to_owned()]);
    loop {
        let before = family.len();
        for alias in aliases {
            if family.contains(&alias.left) || family.contains(&alias.right) {
                family.insert(alias.left.clone());
                family.insert(alias.right.clone());
            }
        }
        for (_, file) in files {
            expand_items(&file.items, &mut family);
        }
        if family.len() == before {
            return family;
        }
    }
}

pub fn type_contains(ty: &Type, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_type(ty))
}

pub fn signature_contains(signature: &syn::Signature, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_signature(signature))
}

pub fn path_contains(path: &syn::Path, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_path(path))
}

pub fn trait_contains(item: &syn::ItemTrait, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_item_trait(item))
}

pub fn trait_alias_contains(item: &syn::ItemTraitAlias, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_item_trait_alias(item))
}

pub fn foreign_mod_contains(item: &syn::ItemForeignMod, family: &BTreeSet<String>) -> bool {
    contains(family, |visitor| visitor.visit_item_foreign_mod(item))
}

fn expand_items(items: &[Item], family: &mut BTreeSet<String>) {
    for item in items {
        let candidate = match item {
            Item::Struct(item) if contains(family, |visitor| visitor.visit_item_struct(item)) => {
                Some(&item.ident)
            }
            Item::Enum(item) if contains(family, |visitor| visitor.visit_item_enum(item)) => {
                Some(&item.ident)
            }
            Item::Union(item) if contains(family, |visitor| visitor.visit_item_union(item)) => {
                Some(&item.ident)
            }
            Item::Type(item) if contains(family, |visitor| visitor.visit_item_type(item)) => {
                Some(&item.ident)
            }
            _ => None,
        };
        if let Some(ident) = candidate {
            family.insert(ident_name(ident));
        }
        if let Item::Mod(item) = item
            && let Some((_, nested)) = &item.content
        {
            expand_items(nested, family);
        }
    }
}

fn contains(family: &BTreeSet<String>, inspect: impl FnOnce(&mut FamilyVisitor<'_>)) -> bool {
    let mut visitor = FamilyVisitor {
        family,
        found: false,
    };
    inspect(&mut visitor);
    visitor.found
}

struct FamilyVisitor<'a> {
    family: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for FamilyVisitor<'_> {
    fn visit_type(&mut self, node: &'ast syn::Type) {
        if matches!(node, syn::Type::Macro(_) | syn::Type::Verbatim(_)) {
            self.found = true;
        }
        visit::visit_type(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node
            .segments
            .iter()
            .any(|segment| self.family.contains(&ident_name(&segment.ident)))
        {
            self.found = true;
        }
        visit::visit_path(self, node);
    }
}

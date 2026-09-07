use std::collections::HashSet;

use syn::visit::Visit;

use super::{Source, syntax};

#[derive(Default)]
pub(super) struct Families {
    pub exact: HashSet<String>,
    pub projection: HashSet<String>,
}

pub(super) fn discover(sources: &[Source]) -> Families {
    let mut families = Families::default();
    families
        .exact
        .insert("VerifiedSignedInstalledReleaseV2".into());
    families
        .projection
        .insert("VerifiedCandidateBindingV3".into());
    loop {
        let before = families.exact.len() + families.projection.len();
        for source in sources {
            let (exact, projection) = {
                let mut collector = AliasCollector {
                    families: &families,
                    exact: Vec::new(),
                    projection: Vec::new(),
                };
                collector.visit_file(&source.syntax);
                (collector.exact, collector.projection)
            };
            families.exact.extend(exact);
            families.projection.extend(projection);
        }
        if before == families.exact.len() + families.projection.len() {
            return families;
        }
    }
}

struct AliasCollector<'a> {
    families: &'a Families,
    exact: Vec<String>,
    projection: Vec<String>,
}

impl<'ast> Visit<'ast> for AliasCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !syntax::item_is_test_only(item) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !syntax::impl_item_is_test_only(item) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !syntax::trait_item_is_test_only(item) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !syntax::is_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        for leaf in syntax::use_leaves(&item.tree) {
            let Some(local) = leaf.local else { continue };
            if leaf
                .segments
                .iter()
                .any(|name| self.families.exact.contains(name))
            {
                self.exact.push(local.clone());
            }
            if leaf
                .segments
                .iter()
                .any(|name| self.families.projection.contains(name))
            {
                self.projection.push(local);
            }
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        if syntax::alias_mentions(item, &self.families.exact) {
            self.exact.push(item.ident.to_string());
        }
        if syntax::alias_mentions(item, &self.families.projection) {
            self.projection.push(item.ident.to_string());
        }
    }

    // Names from guarded associated assignments/defaults are intentionally
    // scope-insensitive, as with ordinary aliases: every same-named associated
    // path, including shorthand T::Value/Self::Value, is treated conservatively.
    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if syntax::impl_type_mentions(item, &self.families.exact) {
            self.exact.push(item.ident.to_string());
        }
        if syntax::impl_type_mentions(item, &self.families.projection) {
            self.projection.push(item.ident.to_string());
        }
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if syntax::trait_type_mentions(item, &self.families.exact) {
            self.exact.push(item.ident.to_string());
        }
        if syntax::trait_type_mentions(item, &self.families.projection) {
            self.projection.push(item.ident.to_string());
        }
    }
}

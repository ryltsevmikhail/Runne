use std::collections::HashSet;

use syn::visit::{self, Visit};
use syn::{ImplItem, ItemUse, Visibility};

use crate::installed_surface_consumers::{
    exact_reviewed_consumer_method, exact_reviewed_consumer_struct,
};
use crate::installed_surface_daemon::{
    exact_daemon_carrier, exact_fence_reverification, exact_fence_wrapper, exact_initial_read,
    exact_initial_result, exact_retention_helper, exact_session_carrier, exact_session_transfer,
};
use crate::installed_surface_expected::{
    exact_reviewed_facts_method, exact_test_only_qualification_facts,
};
use crate::installed_surface_macros::mentions_authority;
use crate::installed_surface_syntax::{
    EXPECTATION, FACTS, VERIFIED, collect_aliases, collect_macro_aliases, collect_sealed_aliases,
    exact_factory, exact_reviewed_reexport, exact_test_support_only, exact_verification,
    fields_mention, generics_mention, impl_member_mentions, node_mentions_trait, path_mentions,
    sealed_struct, signature_mentions, type_mentions, type_name, use_leaves,
};

#[derive(Default)]
pub struct Audit {
    pub facts: usize,
    pub expectation: usize,
    pub verified: usize,
    pub factory: usize,
    pub verification: usize,
    pub retention: usize,
    pub initial_result: usize,
    pub facts_reexports: usize,
    pub violations: Vec<String>,
}

struct SourceAudit<'a> {
    source: &'a str,
    aliases: HashSet<String>,
    sealed_aliases: HashSet<String>,
    macro_aliases: HashSet<String>,
    audit: &'a mut Audit,
}

impl<'ast> Visit<'ast> for SourceAudit<'_> {
    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        let name = item.ident.to_string();
        if name == FACTS {
            self.audit.facts += 1;
            if !matches!(item.vis, Visibility::Public(_)) || !sealed_struct(item) {
                self.reject("installed facts are not constructor-sealed");
            }
        } else if name == EXPECTATION {
            self.audit.expectation += 1;
            if !matches!(item.vis, Visibility::Inherited) || !sealed_struct(item) {
                self.reject("installed expectation is externally constructible");
            }
        } else if name == VERIFIED {
            self.audit.verified += 1;
            if !exact_daemon_carrier(self.source, item) {
                self.reject("verified admission is reusable or externally constructible");
            }
        } else {
            let sealed = fields_mention(&item.fields, &self.sealed_aliases)
                || generics_mention(&item.generics, &self.sealed_aliases);
            let public_facts = matches!(item.vis, Visibility::Public(_))
                && (fields_mention(&item.fields, &self.aliases)
                    || generics_mention(&item.generics, &self.aliases));
            if (sealed
                && !exact_session_carrier(self.source, item, &self.sealed_aliases)
                && !exact_fence_wrapper(self.source, item))
                || (public_facts && !exact_reviewed_consumer_struct(self.source, item))
            {
                self.reject("public generic or field wrapper escapes a sealed type");
            }
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let owner = type_name(&item.self_ty, &self.aliases);
        if owner.as_deref() == Some(EXPECTATION) || owner.as_deref() == Some(VERIFIED) {
            if owner.as_deref() == Some(VERIFIED) && exact_fence_reverification(self.source, item) {
                return;
            }
            if item.trait_.is_some() || !item.items.is_empty() {
                self.reject("sealed token has an impl, getter, predicate, constructor, or trait");
            }
            return;
        }
        if owner.as_deref() == Some(FACTS) {
            self.audit_facts_impl(item);
            return;
        }
        if type_mentions(&item.self_ty, &self.aliases)
            || generics_mention(&item.generics, &self.aliases)
            || item
                .trait_
                .as_ref()
                .is_some_and(|(_, path, _)| path_mentions(path, &self.aliases))
        {
            self.reject("wrapper or trait impl mentions a sealed installed type");
        }
        for member in &item.items {
            if impl_member_mentions(member, &self.sealed_aliases) {
                if !matches!(member, ImplItem::Fn(method) if exact_session_transfer(self.source, &item.self_ty, method))
                {
                    self.reject("impl member escapes a sealed installed token");
                }
            } else if impl_member_mentions(member, &self.aliases) {
                match member {
                    ImplItem::Fn(method)
                        if !matches!(method.vis, Visibility::Public(_))
                            || exact_reviewed_consumer_method(self.source, method) => {}
                    _ => self.reject("unreviewed public installed-facts consumer method"),
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if exact_retention_helper(self.source, item) {
            self.audit.retention += 1;
        } else if !exact_initial_read(self.source, item)
            && (signature_mentions(&item.sig, &self.sealed_aliases)
                || (matches!(item.vis, Visibility::Public(_))
                    && signature_mentions(&item.sig, &self.aliases)))
        {
            self.reject("free function mentions a sealed installed type");
        }
        visit::visit_item_fn(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        let carries_sealed = item
            .variants
            .iter()
            .flat_map(|variant| variant.fields.iter())
            .any(|field| type_mentions(&field.ty, &self.sealed_aliases));
        if carries_sealed {
            if exact_initial_result(self.source, item) {
                self.audit.initial_result += 1;
            } else {
                self.reject("enum escapes a sealed installed token");
            }
        }
        visit::visit_item_enum(self, item);
    }

    fn visit_foreign_item_fn(&mut self, item: &'ast syn::ForeignItemFn) {
        if signature_mentions(&item.sig, &self.aliases) {
            self.reject("foreign function mentions a sealed installed type");
        }
        visit::visit_foreign_item_fn(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if type_mentions(&item.ty, &self.aliases) || generics_mention(&item.generics, &self.aliases)
        {
            self.reject("type or generic alias mentions a sealed installed type");
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if node_mentions_trait(item, &self.aliases) {
            self.reject("trait or associated type mentions a sealed installed type");
        }
        visit::visit_item_trait(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        if !matches!(item.vis, Visibility::Inherited) {
            for leaf in use_leaves(&item.tree) {
                let sensitive = leaf.last().is_some_and(|name| self.aliases.contains(name));
                if sensitive && exact_reviewed_reexport(self.source, &leaf) {
                    self.audit.facts_reexports += 1;
                } else if sensitive || leaf.last().is_some_and(|name| name == "*") {
                    self.reject("reexport, rename, or glob escapes a sealed installed type");
                }
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if mentions_authority(item, &self.macro_aliases) {
            self.reject("macro definition or invocation mentions a sealed installed type");
        }
        visit::visit_item_macro(self, item);
    }
}

impl SourceAudit<'_> {
    fn audit_facts_impl(&mut self, item: &syn::ItemImpl) {
        if exact_test_support_only(&item.attrs) {
            if item.trait_.is_none()
                && item.items.len() == 1
                && matches!(&item.items[0], ImplItem::Fn(method)
                    if exact_test_only_qualification_facts(method))
            {
                return;
            }
            self.reject("test-only installed-facts seam is not exact");
            return;
        }
        if item.trait_.is_some() || generics_mention(&item.generics, &self.aliases) {
            self.reject("installed facts gain a trait or generic authority surface");
        }
        for member in &item.items {
            match member {
                ImplItem::Fn(method)
                    if method.sig.ident == "qualification_runtime_installed_expectation" =>
                {
                    if matches!(method.vis, Visibility::Inherited) && exact_factory(&method.sig) {
                        self.audit.factory += 1;
                    } else {
                        self.reject("installed expectation factory is not exact/private");
                    }
                }
                ImplItem::Fn(method) if method.sig.ident == "verify_qualification_admission" => {
                    if matches!(method.vis, Visibility::Public(_))
                        && exact_verification(&method.sig)
                    {
                        self.audit.verification += 1;
                    } else {
                        self.reject("verified admission mint is not exact/private");
                    }
                }
                ImplItem::Fn(method) if exact_reviewed_facts_method(method) => {}
                ImplItem::Fn(_) => self.reject("unreviewed installed-facts impl surface"),
                ImplItem::Type(_) | ImplItem::Const(_) => {
                    self.reject("installed facts gain an associated escape surface");
                }
                _ => {}
            }
        }
    }

    fn reject(&mut self, message: &str) {
        self.audit
            .violations
            .push(format!("{}: {message}", self.source));
    }
}

pub fn audit_sources(sources: &[(&str, &str)]) -> Audit {
    let mut audit = Audit::default();
    for (path, source) in sources {
        if ![FACTS, EXPECTATION, VERIFIED]
            .iter()
            .any(|name| source.contains(name))
        {
            continue;
        }
        let file = syn::parse_file(source).unwrap();
        let aliases = collect_aliases(&file);
        let sealed_aliases = collect_sealed_aliases(&file);
        let macro_aliases = collect_macro_aliases(&file);
        SourceAudit {
            source: path,
            aliases,
            sealed_aliases,
            macro_aliases,
            audit: &mut audit,
        }
        .visit_file(&file);
    }
    audit
}

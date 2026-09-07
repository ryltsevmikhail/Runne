use std::collections::HashSet;

use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprStruct, ItemImpl, ItemStruct};

use super::surface_ingress as ingress;
use super::surface_policy::{self as policy, Stats};
use super::surface_syntax as syntax;

struct Source {
    path: String,
    syntax: syn::File,
}

#[path = "signed_release_surface_families.rs"]
mod families;
use families::Families;

pub fn audit(sources: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let parsed = sources
        .iter()
        .filter_map(|(path, contents)| match syn::parse_file(contents) {
            Ok(syntax) => Some(Source {
                path: path.replace('\\', "/"),
                syntax,
            }),
            Err(error) => {
                violations.push(format!("parse failure in {path}: {error}"));
                None
            }
        })
        .collect::<Vec<_>>();
    let families = families::discover(&parsed);
    let mut stats = Stats::default();
    for source in &parsed {
        let mut auditor = Auditor {
            path: &source.path,
            families: &families,
            stats: &mut stats,
            violations: &mut violations,
        };
        auditor.visit_file(&source.syntax);
    }
    policy::validate_counts(&stats, &mut violations);
    violations.sort();
    violations.dedup();
    violations
}

struct Auditor<'a> {
    path: &'a str,
    families: &'a Families,
    stats: &'a mut Stats,
    violations: &'a mut Vec<String>,
}

impl Auditor<'_> {
    fn reject(&mut self, category: &str, detail: impl std::fmt::Display) {
        self.violations
            .push(format!("{category} in {}: {detail}", self.path));
    }
}

impl<'ast> Visit<'ast> for Auditor<'_> {
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

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        let name = item.ident.to_string();
        if self.families.exact.contains(&name) {
            policy::audit_exact_struct(self.path, item, self.stats, self.violations);
        } else if self.families.projection.contains(&name) {
            policy::audit_projection_struct(self.path, item, self.stats, self.violations);
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        let exact = syntax::type_mentions(&item.self_ty, &self.families.exact);
        let projection = syntax::type_mentions(&item.self_ty, &self.families.projection);
        let conversion = item.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "From" | "Into" | "TryFrom" | "TryInto"
                )
            })
        });
        if exact {
            policy::audit_exact_impl(self.path, item, self.stats, self.violations);
        }
        if projection {
            policy::audit_projection_impl(self.path, item, self.stats, self.violations);
        }
        for member in &item.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if syntax::is_test_only(&method.attrs) {
                continue;
            }
            if syntax::signature_mentions(&method.sig, &self.families.exact) {
                ingress::audit_method(self.path, &item.self_ty, method, self.violations);
                if syntax::has_cfg_attr(&item.attrs) {
                    self.reject("guarded cfg_attr", "exact-release ingress impl");
                }
            }
            if syntax::is_public(&method.vis)
                && syntax::signature_mentions(&method.sig, &self.families.projection)
            {
                self.reject("projection signature", &method.sig.ident);
            }
        }
        if conversion && !exact && trait_or_self_mentions(item, &self.families.exact) {
            self.reject(
                "exact-release conversion",
                "conversion trait mentions exact release",
            );
        }
        if conversion && !projection && trait_or_self_mentions(item, &self.families.projection) {
            self.reject(
                "projection conversion",
                "conversion trait mentions projection",
            );
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if syntax::impl_type_mentions(item, &self.families.exact)
            || syntax::impl_type_mentions(item, &self.families.projection)
        {
            self.reject("guarded associated type", &item.ident);
        }
        syn::visit::visit_impl_item_type(self, item);
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if syntax::trait_type_mentions(item, &self.families.exact)
            || syntax::trait_type_mentions(item, &self.families.projection)
        {
            self.reject("guarded associated type", &item.ident);
        }
        syn::visit::visit_trait_item_type(self, item);
    }

    fn visit_generic_argument(&mut self, argument: &'ast syn::GenericArgument) {
        if let syn::GenericArgument::AssocType(binding) = argument
            && (syntax::type_mentions(&binding.ty, &self.families.exact)
                || syntax::type_mentions(&binding.ty, &self.families.projection))
        {
            self.reject("guarded associated equality", &binding.ident);
        }
        syn::visit::visit_generic_argument(self, argument);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if syntax::signature_mentions(&item.sig, &self.families.exact)
            || syntax::signature_mentions(&item.sig, &self.families.projection)
        {
            self.reject("guarded associated signature", &item.sig.ident);
        }
        syn::visit::visit_trait_item_fn(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        if syntax::is_public(&item.vis) {
            for leaf in syntax::use_leaves(&item.tree) {
                if leaf
                    .segments
                    .iter()
                    .any(|name| self.families.projection.contains(name))
                    || (leaf.glob && leaf.segments.iter().any(|name| name == "candidate_binding"))
                {
                    self.reject("projection reexport", "public use exposes projection");
                }
            }
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        if syntax::alias_mentions(item, &self.families.projection) {
            self.reject("projection alias", item.ident.to_string());
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if syntax::is_test_only(&item.attrs) {
            return;
        }
        if syntax::signature_mentions(&item.sig, &self.families.exact) {
            ingress::audit_free(self.path, item, self.violations);
        }
        if syntax::is_public(&item.vis)
            && syntax::signature_mentions(&item.sig, &self.families.projection)
        {
            self.reject("projection signature", item.sig.ident.to_string());
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_expr_struct(&mut self, expression: &'ast ExprStruct) {
        if syntax::path_mentions(&expression.path, &self.families.exact) {
            self.stats.exact_constructions.push(self.path.into());
        }
        syn::visit::visit_expr_struct(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Expr::Path(function) = expression.func.as_ref() {
            let owner =
                function.qself.as_ref().is_some_and(|qself| {
                    syntax::type_mentions(&qself.ty, &self.families.projection)
                }) || syntax::path_mentions(&function.path, &self.families.projection);
            if owner
                && function
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "from_target")
            {
                self.stats
                    .projection_constructor_calls
                    .push(self.path.into());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

fn trait_or_self_mentions(item: &ItemImpl, names: &HashSet<String>) -> bool {
    syntax::type_mentions(&item.self_ty, names)
        || item
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| syntax::path_mentions(path, names))
}

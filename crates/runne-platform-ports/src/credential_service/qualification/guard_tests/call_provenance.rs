use std::collections::BTreeSet;

use syn::visit::Visit;
use syn::{Item, Signature};

use super::source_semantics::impl_is_qualification;
use super::syntax::normalized_ident;

pub(super) fn same_file_qualification_types(
    items: &[Item],
    names: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    for item in items {
        match item {
            Item::Impl(item) if impl_is_qualification(item, names) => {
                types.extend(super::metadata::type_name(&item.self_ty));
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    types.extend(same_file_qualification_types(nested, names));
                }
            }
            _ => {}
        }
    }
    types
}

pub(super) fn carrier_struct_names(items: &[Item], names: &BTreeSet<String>) -> BTreeSet<String> {
    let mut carriers = BTreeSet::new();
    loop {
        let known = names.union(&carriers).cloned().collect::<BTreeSet<_>>();
        let previous = carriers.len();
        for item in items {
            let Item::Struct(structure) = item else {
                continue;
            };
            if structure
                .fields
                .iter()
                .any(|field| super::visitor_types::type_mentions_names(&field.ty, &known))
            {
                carriers.insert(normalized_ident(&structure.ident));
            }
        }
        if carriers.len() == previous {
            return carriers;
        }
    }
}

pub(super) fn qualification_factory_names(
    items: &[Item],
    names: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut factories = BTreeSet::new();
    for item in items {
        match item {
            Item::Fn(function) => {
                if let syn::ReturnType::Type(_, ty) = &function.sig.output
                    && super::visitor_types::type_mentions_names(ty, names)
                {
                    factories.insert(normalized_ident(&function.sig.ident));
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    factories.extend(qualification_factory_names(nested, names));
                }
            }
            Item::Impl(item) => {
                for member in &item.items {
                    if let syn::ImplItem::Fn(function) = member
                        && let syn::ReturnType::Type(_, ty) = &function.sig.output
                        && super::visitor_types::type_mentions_names(ty, names)
                    {
                        factories.insert(normalized_ident(&function.sig.ident));
                    }
                }
            }
            Item::Trait(item) => {
                for member in &item.items {
                    if let syn::TraitItem::Fn(function) = member
                        && let syn::ReturnType::Type(_, ty) = &function.sig.output
                        && super::visitor_types::type_mentions_names(ty, names)
                    {
                        factories.insert(normalized_ident(&function.sig.ident));
                    }
                }
            }
            _ => {}
        }
    }
    factories
}

pub(super) fn classify_local_qualify_receivers(
    items: &[Item],
    qualification_names: &mut BTreeSet<String>,
    unrelated: &mut BTreeSet<String>,
) {
    for item in items {
        let Item::Trait(local) = item else { continue };
        let name = normalized_ident(&local.ident);
        let inherited: BTreeSet<String> = qualification_names
            .iter()
            .filter(|candidate| **candidate != name)
            .cloned()
            .collect();
        let extends_qualification = local.supertraits.iter().any(|bound| {
            matches!(bound, syn::TypeParamBound::Trait(bound) if bound.path.segments.last().is_some_and(|segment| inherited.contains(&normalized_ident(&segment.ident))))
        });
        if qualification_names.contains(&name) && !extends_qualification {
            qualification_names.remove(&name);
            unrelated.insert(name);
        }
    }
    for item in items {
        let Item::Impl(item) = item else { continue };
        let Some(name) = super::metadata::type_name(&item.self_ty) else {
            continue;
        };
        if impl_is_qualification(item, qualification_names) {
            unrelated.remove(&name);
        } else if item.items.iter().any(|member| {
            matches!(member, syn::ImplItem::Fn(function) if function.sig.ident == "qualify")
        }) {
            unrelated.insert(name);
        }
    }
    loop {
        let previous = (qualification_names.clone(), unrelated.clone());
        for item in items {
            let Item::Type(alias) = item else { continue };
            let alias_name = normalized_ident(&alias.ident);
            if super::visitor_types::type_mentions_names(&alias.ty, qualification_names) {
                unrelated.remove(&alias_name);
                qualification_names.insert(alias_name);
            } else if super::visitor_types::type_mentions_names(&alias.ty, unrelated) {
                qualification_names.remove(&alias_name);
                unrelated.insert(alias_name);
            }
        }
        if previous == (qualification_names.clone(), unrelated.clone()) {
            break;
        }
    }
}

pub(super) fn signature_mentions(
    signature: &Signature,
    names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
) -> bool {
    struct Visitor<'a> {
        names: &'a BTreeSet<String>,
        qualified_names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
            self.found |= path_is_qualification(&bound.path, self.names, self.qualified_names);
            syn::visit::visit_trait_bound(self, bound);
        }
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.found |= path_is_qualification(&path.path, self.names, self.qualified_names);
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut visitor = Visitor {
        names,
        qualified_names,
        found: false,
    };
    visitor.visit_signature(signature);
    visitor.found
}

pub(super) fn type_mentions_qualification(
    ty: &syn::Type,
    names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
) -> bool {
    struct Visitor<'a> {
        names: &'a BTreeSet<String>,
        qualified_names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
            self.found |= path_is_qualification(&bound.path, self.names, self.qualified_names);
            syn::visit::visit_trait_bound(self, bound);
        }

        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.found |= path_is_qualification(&path.path, self.names, self.qualified_names);
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut visitor = Visitor {
        names,
        qualified_names,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

pub(super) fn expression_mentions_qualification_type(
    expression: &syn::Expr,
    names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
) -> bool {
    struct Visitor<'a> {
        names: &'a BTreeSet<String>,
        qualified_names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_type(&mut self, ty: &'ast syn::Type) {
            self.found |= type_mentions_qualification(ty, self.names, self.qualified_names);
            syn::visit::visit_type(self, ty);
        }
    }
    let mut visitor = Visitor {
        names,
        qualified_names,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

fn path_is_qualification(
    path: &syn::Path,
    names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
) -> bool {
    let segments = path
        .segments
        .iter()
        .map(|segment| normalized_ident(&segment.ident))
        .collect::<Vec<_>>();
    segments.last().is_some_and(|name| names.contains(name))
        || (segments.len() > 1
            && segments.last().is_some_and(|name| {
                name == super::QUALIFICATION_PORT || qualified_names.contains(name)
            }))
}

pub(super) fn struct_names(items: &[Item]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in items {
        match item {
            Item::Struct(item) => {
                names.insert(item.ident.to_string());
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    names.extend(struct_names(nested));
                }
            }
            _ => {}
        }
    }
    names
}

pub(super) fn trait_is_qualification(item: &syn::ItemTrait, names: &BTreeSet<String>) -> bool {
    names.contains(item.ident.to_string().as_str())
}

use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Item, ItemTrait, Signature, TraitItem};

use super::bodies;
use super::macro_definitions;
use super::macro_scope;
use super::syntax::impl_item_is_test_only;
use super::visitor::{Call, CallVisitor, macro_mentions_names};
use super::{QUALIFICATION_PORT, impl_is_qualification, item_attrs, item_is_test_only};

#[derive(Clone, Copy)]
enum AttributeTarget {
    Function,
    Impl,
    Trait,
}

pub(super) fn collect(
    items: &[Item],
    local_names: &BTreeSet<String>,
    concrete_names: &BTreeSet<String>,
) -> (Vec<Call>, macro_definitions::Index) {
    let definitions = macro_definitions::index(items);
    let mut calls = Vec::new();
    let mut callable_names = local_names.clone();
    callable_names.extend(concrete_names.iter().cloned());
    collect_calls(items, &callable_names, &mut calls, &[]);
    (calls, definitions)
}

fn collect_calls(
    items: &[Item],
    local_names: &BTreeSet<String>,
    calls: &mut Vec<Call>,
    scope: &[String],
) {
    for item in items {
        if item_is_test_only(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Trait(item) if trait_is_qualification(item, local_names) => {
                collect_opaque_attribute(&item.attrs, AttributeTarget::Trait, calls);
                bodies::collect_trait_bodies(item, calls);
            }
            Item::Trait(item) => collect_trait_calls(item, local_names, calls),
            Item::Impl(item) if impl_is_qualification(item, local_names) => {
                collect_opaque_attribute(&item.attrs, AttributeTarget::Impl, calls);
                bodies::collect_impl_bodies(item, calls);
            }
            Item::Impl(item) => collect_impl_calls(item, local_names, calls, scope),
            Item::Macro(item) => {
                if !item.mac.path.is_ident("macro_rules")
                    && macro_mentions_names(&item.mac.tokens, local_names)
                {
                    let mut visitor = CallVisitor::qualification_context();
                    visitor.visit_macro(&item.mac);
                    calls.extend(visitor.calls);
                }
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    let nested_scope =
                        macro_scope::child(scope, &item.ident.to_string(), item.span());
                    collect_calls(nested, local_names, calls, &nested_scope);
                }
            }
            Item::Fn(item) => {
                let qualification_context = signature_mentions(&item.sig, local_names);
                if qualification_context {
                    collect_opaque_attribute(&item.attrs, AttributeTarget::Function, calls);
                }
                let function_scope =
                    macro_scope::child(scope, &item.sig.ident.to_string(), item.span());
                let mut visitor =
                    CallVisitor::for_function(local_names, qualification_context, function_scope);
                visitor.seed_typed_receivers(&item.block);
                visitor.visit_item_fn(item);
                calls.extend(visitor.calls);
            }
            _ => {
                let mut visitor = CallVisitor::new();
                visitor.visit_item(item);
                calls.extend(visitor.calls);
            }
        }
    }
}

fn collect_impl_calls(
    item: &syn::ItemImpl,
    local_names: &BTreeSet<String>,
    calls: &mut Vec<Call>,
    scope: &[String],
) {
    for member in &item.items {
        if impl_item_is_test_only(member) {
            continue;
        }
        let syn::ImplItem::Fn(function) = member else {
            continue;
        };
        let context = signature_mentions(&function.sig, local_names);
        let function_scope =
            macro_scope::child(scope, &function.sig.ident.to_string(), function.span());
        let mut visitor = CallVisitor::for_function(local_names, context, function_scope);
        visitor.seed_typed_receivers(&function.block);
        visitor.visit_impl_item_fn(function);
        calls.extend(visitor.calls);
    }
}

fn collect_trait_calls(item: &ItemTrait, local_names: &BTreeSet<String>, calls: &mut Vec<Call>) {
    for trait_item in &item.items {
        let TraitItem::Fn(function) = trait_item else {
            continue;
        };
        let mut visitor = if signature_mentions(&function.sig, local_names) {
            CallVisitor::qualification_context()
        } else {
            CallVisitor::new()
        };
        visitor.visit_trait_item_fn(function);
        calls.extend(visitor.calls);
    }
}

fn trait_is_qualification(item: &ItemTrait, names: &BTreeSet<String>) -> bool {
    item.ident == QUALIFICATION_PORT || names.contains(item.ident.to_string().as_str())
}

fn collect_opaque_attribute(attrs: &[Attribute], target: AttributeTarget, calls: &mut Vec<Call>) {
    let Some(attribute) = attrs
        .iter()
        .find(|attribute| !is_non_expanding_builtin(attribute, target))
    else {
        return;
    };
    calls.push(Call::Macro {
        name: attribute
            .path()
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default(),
        unqualified: false,
        qualification_context: true,
        selects_qualification: false,
        scope: Vec::new(),
        position: 0,
    });
}

fn is_non_expanding_builtin(attribute: &Attribute, target: AttributeTarget) -> bool {
    if is_inert_tool_attribute(attribute) {
        return true;
    }
    let Some(name) = attribute.path().get_ident().map(ToString::to_string) else {
        return is_diagnostic_builtin(attribute, target);
    };
    if matches!(
        name.as_str(),
        "allow" | "cfg" | "deprecated" | "deny" | "doc" | "expect" | "forbid" | "must_use" | "warn"
    ) {
        return true;
    }
    match target {
        AttributeTarget::Function => {
            matches!(
                name.as_str(),
                "cold" | "inline" | "instruction_set" | "target_feature" | "track_caller"
            ) || (name == "unsafe" && is_non_expanding_unsafe_builtin(attribute))
        }
        AttributeTarget::Impl => name == "automatically_derived",
        AttributeTarget::Trait => false,
    }
}

fn is_inert_tool_attribute(attribute: &Attribute) -> bool {
    attribute.path().segments.first().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "clippy" | "miri" | "rust_analyzer" | "rustfmt"
        )
    })
}

fn is_diagnostic_builtin(attribute: &Attribute, target: AttributeTarget) -> bool {
    let path = attribute.path();
    let mut segments = path.segments.iter();
    let pair = segments
        .next()
        .zip(segments.next())
        .filter(|_| segments.next().is_none());
    pair.is_some_and(|(tool, name)| {
        tool.ident == "diagnostic"
            && matches!(
                (target, name.ident.to_string().as_str()),
                (AttributeTarget::Trait, "on_unimplemented")
                    | (AttributeTarget::Impl, "do_not_recommend")
            )
    })
}

fn is_non_expanding_unsafe_builtin(attribute: &Attribute) -> bool {
    attribute.parse_args::<syn::Meta>().is_ok_and(|meta| {
        matches!(
            meta.path().get_ident().map(ToString::to_string).as_deref(),
            Some("export_name" | "link_section" | "naked" | "no_mangle")
        )
    })
}

fn signature_mentions(signature: &Signature, names: &BTreeSet<String>) -> bool {
    struct Visitor<'a> {
        names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
            self.found |= bound
                .path
                .segments
                .last()
                .is_some_and(|segment| self.names.contains(&segment.ident.to_string()));
            syn::visit::visit_trait_bound(self, bound);
        }
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.found |= path
                .path
                .segments
                .last()
                .is_some_and(|segment| self.names.contains(&segment.ident.to_string()));
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut visitor = Visitor {
        names,
        found: false,
    };
    visitor.visit_signature(signature);
    visitor.found
}

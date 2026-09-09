use std::collections::BTreeSet;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Item, ItemTrait, TraitItem};

use super::attributes::{self, AttributeTarget};
use super::bodies;
use super::call_provenance::{
    carrier_struct_names, classify_local_qualify_receivers, qualification_factory_names,
    same_file_qualification_types, signature_mentions, struct_names, trait_is_qualification,
};
use super::macro_definitions;
use super::macro_scope;
use super::source_semantics::impl_is_qualification;
use super::syntax::impl_item_is_test_only;
use super::visitor::{Call, CallVisitor};
use super::{item_attrs, item_is_test_only};

#[path = "call_item_macro.rs"]
mod call_item_macro;

pub(super) fn collect(
    items: &[Item],
    local_names: &BTreeSet<String>,
    concrete_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    trusted_external_roots: &BTreeSet<String>,
) -> (Vec<Call>, macro_definitions::Index) {
    let definitions = macro_definitions::index(items, trusted_external_roots);
    let mut calls = Vec::new();
    let mut callable_names = local_names.clone();
    callable_names.extend(concrete_names.iter().cloned());
    let opaque_container_names = struct_names(items);
    let mut carrier_bases = same_file_qualification_types(items, local_names);
    carrier_bases.insert(super::QUALIFICATION_PORT.to_owned());
    callable_names.extend(carrier_struct_names(items, &carrier_bases));
    callable_names.extend(qualification_factory_names(items, &callable_names));
    collect_calls(
        items,
        &callable_names,
        &callable_names,
        &opaque_container_names,
        unrelated_type_names,
        &mut calls,
        &[],
    );
    (calls, definitions)
}

fn collect_calls(
    items: &[Item],
    local_names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
    opaque_container_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    calls: &mut Vec<Call>,
    scope: &[String],
) {
    for item in items {
        if item_is_test_only(item_attrs(item)) {
            continue;
        }
        collect_non_callable_attributes(item, calls);
        match item {
            Item::Trait(item) if trait_is_qualification(item, local_names) => {
                attributes::collect_opaque_attribute(&item.attrs, AttributeTarget::Trait, calls);
                for member in &item.items {
                    if !super::syntax::trait_item_is_test_only(member) {
                        attributes::collect_opaque_attribute(
                            attributes::trait_item_attrs(member),
                            AttributeTarget::Other,
                            calls,
                        );
                    }
                }
                bodies::collect_trait_bodies(item, calls);
                call_item_macro::collect_qualification_trait(item, scope, calls);
            }
            Item::Trait(item) => {
                collect_trait_calls(
                    item,
                    local_names,
                    qualified_names,
                    unrelated_type_names,
                    scope,
                    calls,
                );
            }
            Item::Impl(item) if impl_is_qualification(item, local_names) => {
                attributes::collect_opaque_attribute(&item.attrs, AttributeTarget::Impl, calls);
                for member in &item.items {
                    if !impl_item_is_test_only(member) {
                        attributes::collect_opaque_attribute(
                            attributes::impl_item_attrs(member),
                            AttributeTarget::Other,
                            calls,
                        );
                    }
                }
                bodies::collect_impl_bodies(item, calls);
                call_item_macro::collect_qualification_impl(item, scope, calls);
            }
            Item::Impl(item) => collect_impl_calls(
                item,
                local_names,
                qualified_names,
                opaque_container_names,
                unrelated_type_names,
                calls,
                scope,
            ),
            Item::Macro(item) => call_item_macro::collect(
                &item.mac,
                local_names,
                qualified_names,
                unrelated_type_names,
                scope,
                calls,
            ),
            Item::Mod(item) => {
                collect_nested_module(
                    item,
                    local_names,
                    qualified_names,
                    opaque_container_names,
                    unrelated_type_names,
                    calls,
                    scope,
                );
            }
            Item::Fn(item) => {
                let qualification_context =
                    signature_mentions(&item.sig, local_names, qualified_names);
                attributes::collect_opaque_attribute(&item.attrs, AttributeTarget::Function, calls);
                let function_scope =
                    macro_scope::child(scope, &item.sig.ident.to_string(), item.span());
                let mut visitor = CallVisitor::for_function(
                    local_names,
                    qualified_names,
                    qualification_context,
                    function_scope,
                    opaque_container_names,
                    unrelated_type_names,
                );
                visitor.seed_signature_receivers(&item.sig);
                visitor.seed_typed_receivers(&item.block);
                visitor.visit_block(&item.block);
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

fn collect_nested_module(
    item: &syn::ItemMod,
    local_names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
    opaque_container_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    calls: &mut Vec<Call>,
    scope: &[String],
) {
    let Some((_, nested)) = &item.content else {
        return;
    };
    let nested_scope = macro_scope::child(scope, &item.ident.to_string(), item.span());
    let mut nested_names = local_names.clone();
    let mut nested_unrelated = unrelated_type_names.clone();
    classify_local_qualify_receivers(nested, &mut nested_names, &mut nested_unrelated);
    collect_calls(
        nested,
        &nested_names,
        qualified_names,
        opaque_container_names,
        &nested_unrelated,
        calls,
        &nested_scope,
    );
}

fn collect_non_callable_attributes(item: &Item, calls: &mut Vec<Call>) {
    if !matches!(item, Item::Fn(_) | Item::Impl(_) | Item::Trait(_)) {
        attributes::collect_opaque_attribute(item_attrs(item), AttributeTarget::Other, calls);
    }
}

fn collect_impl_calls(
    item: &syn::ItemImpl,
    local_names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
    opaque_container_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    calls: &mut Vec<Call>,
    scope: &[String],
) {
    for member in &item.items {
        if impl_item_is_test_only(member) {
            continue;
        }
        if let syn::ImplItem::Macro(member) = member {
            call_item_macro::collect(
                &member.mac,
                local_names,
                qualified_names,
                unrelated_type_names,
                scope,
                calls,
            );
            continue;
        }
        let syn::ImplItem::Fn(function) = member else {
            attributes::collect_opaque_attribute(
                attributes::impl_item_attrs(member),
                AttributeTarget::Other,
                calls,
            );
            let mut visitor = CallVisitor::new();
            visitor.visit_impl_item(member);
            calls.extend(visitor.calls);
            continue;
        };
        attributes::collect_opaque_attribute(&function.attrs, AttributeTarget::Function, calls);
        let context = signature_mentions(&function.sig, local_names, qualified_names);
        let function_scope =
            macro_scope::child(scope, &function.sig.ident.to_string(), function.span());
        let mut visitor = CallVisitor::for_function(
            local_names,
            qualified_names,
            context,
            function_scope,
            opaque_container_names,
            unrelated_type_names,
        );
        visitor.seed_signature_receivers(&function.sig);
        visitor.seed_typed_receivers(&function.block);
        visitor.visit_block(&function.block);
        calls.extend(visitor.calls);
    }
}

fn collect_trait_calls(
    item: &ItemTrait,
    local_names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    scope: &[String],
    calls: &mut Vec<Call>,
) {
    for trait_item in &item.items {
        if let TraitItem::Macro(member) = trait_item {
            call_item_macro::collect(
                &member.mac,
                local_names,
                qualified_names,
                unrelated_type_names,
                scope,
                calls,
            );
            continue;
        }
        let TraitItem::Fn(function) = trait_item else {
            attributes::collect_opaque_attribute(
                attributes::trait_item_attrs(trait_item),
                AttributeTarget::Other,
                calls,
            );
            let mut visitor = CallVisitor::new();
            visitor.visit_trait_item(trait_item);
            calls.extend(visitor.calls);
            continue;
        };
        attributes::collect_opaque_attribute(&function.attrs, AttributeTarget::Function, calls);
        let mut visitor = if signature_mentions(&function.sig, local_names, qualified_names) {
            CallVisitor::qualification_context()
        } else {
            let mut visitor = CallVisitor::for_function(
                local_names,
                qualified_names,
                false,
                Vec::new(),
                &BTreeSet::new(),
                unrelated_type_names,
            );
            visitor.unrelated_receivers.insert("self".to_owned());
            visitor.seed_signature_receivers(&function.sig);
            visitor
        };
        visitor.visit_trait_item_fn(function);
        calls.extend(visitor.calls);
    }
}

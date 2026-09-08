use syn::visit::Visit;
use syn::{ImplItem, ItemImpl, ItemTrait, TraitItem};

use super::syntax::{impl_item_is_test_only, trait_item_is_test_only};
use super::visitor::{Call, CallVisitor};

pub(super) fn collect_trait_bodies(item: &ItemTrait, calls: &mut Vec<Call>) {
    for trait_item in &item.items {
        if trait_item_is_test_only(trait_item) {
            continue;
        }
        let TraitItem::Fn(function) = trait_item else {
            continue;
        };
        if function.default.is_none() {
            continue;
        }
        let mut visitor = CallVisitor::qualification_body();
        visitor.visit_trait_item_fn(function);
        calls.extend(visitor.calls);
    }
}

pub(super) fn collect_impl_bodies(item: &ItemImpl, calls: &mut Vec<Call>) {
    for impl_item in &item.items {
        if impl_item_is_test_only(impl_item) {
            continue;
        }
        let ImplItem::Fn(function) = impl_item else {
            continue;
        };
        let mut visitor = CallVisitor::qualification_body();
        visitor.visit_impl_item_fn(function);
        calls.extend(visitor.calls);
    }
}

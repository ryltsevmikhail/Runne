use syn::visit::Visit;
use syn::{ImplItem, ItemImpl, ItemTrait, TraitItem};

use super::syntax::{impl_item_is_test_only, trait_item_is_test_only};
use super::visitor::{Call, CallVisitor};

pub(super) fn collect_trait_bodies(item: &ItemTrait, calls: &mut Vec<Call>) {
    for trait_item in &item.items {
        if trait_item_is_test_only(trait_item) {
            continue;
        }
        let mut visitor = CallVisitor::qualification_body();
        match trait_item {
            TraitItem::Fn(function) if function.default.is_some() => {
                visitor.visit_trait_item_fn(function);
            }
            TraitItem::Fn(_) | TraitItem::Macro(_) => continue,
            _ => visitor.visit_trait_item(trait_item),
        }
        calls.extend(visitor.calls);
    }
}

pub(super) fn collect_impl_bodies(item: &ItemImpl, calls: &mut Vec<Call>) {
    for impl_item in &item.items {
        if impl_item_is_test_only(impl_item) {
            continue;
        }
        let mut visitor = CallVisitor::qualification_body();
        match impl_item {
            ImplItem::Fn(function) => visitor.visit_impl_item_fn(function),
            ImplItem::Macro(_) => continue,
            _ => visitor.visit_impl_item(impl_item),
        }
        calls.extend(visitor.calls);
    }
}

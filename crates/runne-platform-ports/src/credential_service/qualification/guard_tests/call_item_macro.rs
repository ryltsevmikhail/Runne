use std::collections::BTreeSet;

use syn::visit::Visit;

use super::super::macro_tokens::macro_mentions_names;
use super::super::visitor::{Call, CallVisitor};

pub(super) fn collect(
    mac: &syn::Macro,
    local_names: &BTreeSet<String>,
    qualified_names: &BTreeSet<String>,
    unrelated_type_names: &BTreeSet<String>,
    scope: &[String],
    calls: &mut Vec<Call>,
) {
    if mac.path.is_ident("macro_rules") {
        return;
    }
    let context = macro_mentions_names(&mac.tokens, qualified_names);
    let mut visitor = CallVisitor::for_function(
        local_names,
        qualified_names,
        context,
        scope.to_vec(),
        &BTreeSet::new(),
        unrelated_type_names,
    );
    visitor.visit_macro(mac);
    calls.extend(visitor.calls);
}

pub(super) fn collect_qualification(mac: &syn::Macro, scope: &[String], calls: &mut Vec<Call>) {
    let mut visitor = CallVisitor::qualification_body();
    visitor.scope = scope.to_vec();
    visitor.visit_macro(mac);
    calls.extend(visitor.calls);
}

pub(super) fn collect_qualification_trait(
    item: &syn::ItemTrait,
    scope: &[String],
    calls: &mut Vec<Call>,
) {
    for member in &item.items {
        if let syn::TraitItem::Macro(member) = member {
            collect_qualification(&member.mac, scope, calls);
        }
    }
}

pub(super) fn collect_qualification_impl(
    item: &syn::ItemImpl,
    scope: &[String],
    calls: &mut Vec<Call>,
) {
    for member in &item.items {
        if let syn::ImplItem::Macro(member) = member {
            collect_qualification(&member.mac, scope, calls);
        }
    }
}

use std::collections::HashSet;

use super::calls::macro_target_call_count;
use super::receiver_facts::Facts;
use super::receiver_helpers::{called_target_method, expression_produces_target};
use super::syntax::is_test_only;
use syn::visit::{self, Visit};
use syn::{Expr, File};

macro_rules! visit_non_test_items {
    ($($method:ident: $item:ty => $delegate:ident),* $(,)?) => {
        $(fn $method(&mut self, node: &'ast $item) {
            if !is_test_only(&node.attrs) { visit::$delegate(self, node); }
        })*
    };
}

pub(super) fn count(file: &File, known: &HashSet<String>, facts: &Facts) -> usize {
    let mut counter = CallCounter {
        known,
        facts,
        count: 0,
    };
    counter.visit_file(file);
    counter.count
}

struct CallCounter<'a> {
    known: &'a HashSet<String>,
    facts: &'a Facts,
    count: usize,
}

impl<'ast> Visit<'ast> for CallCounter<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if called_target_method(
            node.func.as_ref(),
            self.known,
            &self.facts.capture,
            &self.facts.verify,
        )
        .is_some()
        {
            self.count += 1;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "verify_exact"
            && receiver_is_target(node.receiver.as_ref(), self.known, self.facts)
        {
            self.count += 1;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.count += macro_target_call_count(node.tokens.clone(), self.known);
        visit::visit_macro(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if !is_test_only(&node.attrs) {
            self.count += macro_target_call_count(node.mac.tokens.clone(), self.known);
        }
    }

    visit_non_test_items! {
        visit_impl_item_const: syn::ImplItemConst => visit_impl_item_const,
        visit_impl_item_fn: syn::ImplItemFn => visit_impl_item_fn,
        visit_impl_item_macro: syn::ImplItemMacro => visit_impl_item_macro,
        visit_impl_item_type: syn::ImplItemType => visit_impl_item_type,
        visit_item_const: syn::ItemConst => visit_item_const,
        visit_item_enum: syn::ItemEnum => visit_item_enum,
        visit_item_fn: syn::ItemFn => visit_item_fn,
        visit_item_impl: syn::ItemImpl => visit_item_impl,
        visit_item_mod: syn::ItemMod => visit_item_mod,
        visit_item_static: syn::ItemStatic => visit_item_static,
        visit_item_struct: syn::ItemStruct => visit_item_struct,
        visit_item_trait: syn::ItemTrait => visit_item_trait,
        visit_item_union: syn::ItemUnion => visit_item_union,
        visit_trait_item_const: syn::TraitItemConst => visit_trait_item_const,
        visit_trait_item_fn: syn::TraitItemFn => visit_trait_item_fn,
        visit_trait_item_macro: syn::TraitItemMacro => visit_trait_item_macro,
        visit_trait_item_type: syn::TraitItemType => visit_trait_item_type,
    }
}

fn receiver_is_target(expression: &Expr, known: &HashSet<String>, facts: &Facts) -> bool {
    match expression {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| facts.variables.contains(&segment.ident.to_string())),
        Expr::Call(_) | Expr::Try(_) => {
            expression_produces_target(expression, known, &facts.capture, &facts.verify)
        }
        Expr::Cast(cast) => receiver_is_target(&cast.expr, known, facts),
        Expr::Group(group) => receiver_is_target(&group.expr, known, facts),
        Expr::Paren(paren) => receiver_is_target(&paren.expr, known, facts),
        Expr::Reference(reference) => receiver_is_target(&reference.expr, known, facts),
        _ => false,
    }
}

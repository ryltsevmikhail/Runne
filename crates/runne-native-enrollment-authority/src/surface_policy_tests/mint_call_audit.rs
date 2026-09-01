#![cfg(test)]

use std::fs;

use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ImplItemFn, ItemFn, ItemMod, Meta};

use super::source_discovery::production_sources;

#[test]
fn private_session_mint_has_zero_production_call_sites() {
    let mut calls = Vec::new();
    for path in production_sources() {
        let source = fs::read_to_string(&path).unwrap();
        let file = syn::parse_file(&source).unwrap();
        MintCalls {
            source: path.display().to_string(),
            calls: &mut calls,
        }
        .visit_file(&file);
    }
    assert!(calls.is_empty(), "production mint calls: {calls:#?}");
}

struct MintCalls<'a> {
    source: String,
    calls: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for MintCalls<'_> {
    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if !is_test_only(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if matches!(&*node.func, Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "mint"))
        {
            self.calls.push(self.source.clone());
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "mint" {
            self.calls.push(self.source.clone());
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        attribute.path().is_ident("cfg")
            && list
                .parse_args::<Meta>()
                .is_ok_and(|meta| matches!(meta, Meta::Path(path) if path.is_ident("test")))
    })
}

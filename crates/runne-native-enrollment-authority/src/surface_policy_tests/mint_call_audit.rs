#![cfg(test)]

use std::fs;

use syn::visit::{self, Visit};
use syn::{Attribute, ImplItemFn, ItemFn, ItemMacro, ItemMod, Macro, Meta, UseTree};

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

#[test]
fn function_pointer_alias_to_private_mint_is_a_production_call() {
    let file = syn::parse_file(
        "fn bypass() { let alias = AuthenticatedProviderCredentialWriterSession::mint; }",
    )
    .unwrap();
    let mut calls = Vec::new();
    MintCalls {
        source: "mutation".to_owned(),
        calls: &mut calls,
    }
    .visit_file(&file);
    assert_eq!(calls, ["mutation"]);
}

#[test]
fn imported_alias_to_private_mint_is_a_production_call() {
    let file = syn::parse_file(
        "fn bypass() { use AuthenticatedProviderCredentialWriterSession::mint as alias; let _ = alias; }",
    )
    .unwrap();
    let mut calls = Vec::new();
    MintCalls {
        source: "mutation".to_owned(),
        calls: &mut calls,
    }
    .visit_file(&file);
    assert_eq!(calls, ["mutation"]);
}

#[test]
fn macro_tokens_that_mint_a_private_session_are_a_production_call() {
    let file = syn::parse_file(
        "macro_rules! bypass { () => { Self::mint(VerifiedEnrollmentSession::Verified) }; }",
    )
    .unwrap();
    let mut calls = Vec::new();
    MintCalls {
        source: "mutation".to_owned(),
        calls: &mut calls,
    }
    .visit_file(&file);
    assert_eq!(calls, ["mutation"]);
}

#[test]
fn production_source_substitution_cannot_hide_a_private_mint() {
    for source in [
        "fn helper() { include!(\"mint.inc\"); }",
        "#[path = \"mint.rs\"] mod helper;",
        "macro_rules! helper { () => { include!(\"mint.inc\") }; }",
    ] {
        let file = syn::parse_file(source).unwrap();
        let mut calls = Vec::new();
        MintCalls {
            source: "mutation".to_owned(),
            calls: &mut calls,
        }
        .visit_file(&file);
        assert_eq!(calls, ["mutation"], "source substitution escaped: {source}");
    }
}

struct MintCalls<'a> {
    source: String,
    calls: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for MintCalls<'_> {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if node.path().is_ident("path") {
            self.calls.push(self.source.clone());
        }
        visit::visit_attribute(self, node);
    }

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

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_macro(self, node);
        }
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "mint")
        {
            self.calls.push(self.source.clone());
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "mint" {
            self.calls.push(self.source.clone());
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_use_tree(&mut self, node: &'ast UseTree) {
        let imported = match node {
            UseTree::Name(name) => Some(&name.ident),
            UseTree::Rename(rename) => Some(&rename.ident),
            UseTree::Path(path) => Some(&path.ident),
            UseTree::Glob(_) | UseTree::Group(_) => None,
        };
        if imported.is_some_and(|identifier| identifier == "mint") {
            self.calls.push(self.source.clone());
        }
        visit::visit_use_tree(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if node.path.is_ident("include")
            || token_stream_contains_ident(node.tokens.clone(), "mint")
            || token_stream_contains_ident(node.tokens.clone(), "include")
            || token_stream_contains_ident(node.tokens.clone(), "path")
        {
            self.calls.push(self.source.clone());
        }
        visit::visit_macro(self, node);
    }
}

fn token_stream_contains_ident(tokens: proc_macro2::TokenStream, expected: &str) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => identifier == expected,
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_ident(group.stream(), expected)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
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

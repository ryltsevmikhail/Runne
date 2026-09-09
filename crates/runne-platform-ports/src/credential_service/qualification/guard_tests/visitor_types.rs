use std::collections::BTreeSet;

use syn::visit::{self, Visit};

use super::syntax::normalized_ident;

pub(super) fn unwrap_receiver(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match expression {
            syn::Expr::Paren(value) => &value.expr,
            syn::Expr::Group(value) => &value.expr,
            _ => return expression,
        };
    }
}

pub(super) fn type_mentions_names(ty: &syn::Type, names: &BTreeSet<String>) -> bool {
    struct TypeNames<'a> {
        names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for TypeNames<'_> {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.found |= path
                .path
                .segments
                .last()
                .is_some_and(|segment| self.names.contains(&normalized_ident(&segment.ident)));
            visit::visit_type_path(self, path);
        }
        fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
            self.found |= bound
                .path
                .segments
                .last()
                .is_some_and(|segment| self.names.contains(&normalized_ident(&segment.ident)));
            visit::visit_trait_bound(self, bound);
        }
    }
    let mut visitor = TypeNames {
        names,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

pub(super) fn collect_pattern_names(pattern: &syn::Pat, names: &mut BTreeSet<String>) {
    struct Patterns<'a>(&'a mut BTreeSet<String>);
    impl<'ast> Visit<'ast> for Patterns<'_> {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            self.0.insert(normalized_ident(&pattern.ident));
            visit::visit_pat_ident(self, pattern);
        }
    }
    Patterns(names).visit_pat(pattern);
}

pub(super) fn expression_constructs_named_type(
    expression: &syn::Expr,
    names: &BTreeSet<String>,
) -> bool {
    match unwrap_receiver(expression) {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| names.contains(&normalized_ident(&segment.ident))),
        syn::Expr::Struct(structure) => structure
            .path
            .segments
            .last()
            .is_some_and(|segment| names.contains(&normalized_ident(&segment.ident))),
        syn::Expr::Call(call) => match unwrap_receiver(&call.func) {
            syn::Expr::Path(path) => path
                .path
                .segments
                .iter()
                .any(|segment| names.contains(&normalized_ident(&segment.ident))),
            _ => false,
        },
        _ => false,
    }
}

pub(super) fn is_macro_rules_definition(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Macro(macro_) => macro_.mac.path.is_ident("macro_rules"),
        syn::Stmt::Item(syn::Item::Macro(macro_)) => macro_.mac.path.is_ident("macro_rules"),
        _ => false,
    }
}

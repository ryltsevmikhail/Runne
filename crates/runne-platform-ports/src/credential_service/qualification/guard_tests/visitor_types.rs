use std::collections::BTreeSet;

use syn::visit::{self, Visit};

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
                .is_some_and(|segment| self.names.contains(&segment.ident.to_string()));
            visit::visit_type_path(self, path);
        }
        fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
            self.found |= bound
                .path
                .segments
                .last()
                .is_some_and(|segment| self.names.contains(&segment.ident.to_string()));
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
            self.0.insert(pattern.ident.to_string());
            visit::visit_pat_ident(self, pattern);
        }
    }
    Patterns(names).visit_pat(pattern);
}

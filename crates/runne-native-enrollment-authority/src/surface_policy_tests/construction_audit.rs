#![cfg(test)]

//! Guards EVERY production creation site of the authenticated writer session
//! capability, not just named `mint` calls: struct literals of the session and
//! its claim/effect halves, `VerifiedEnrollmentSession` variant constructions
//! (including alias-qualified), and the import/rename/glob/macro routes that
//! could hide them. A future Linux wire verifier may mint ONLY by extending
//! the exact (file, function) reviewed pairs below together with the verifier
//! that performs real live verification — no such site exists today.

use std::fs;

use syn::visit::{self, Visit};
use syn::{Expr, ItemImpl, UseTree};

use super::mint_call_audit::is_test_only;
use super::source_discovery::production_sources;
use super::{CLAIM, EFFECT, SESSION};

#[path = "construction_cases.rs"]
mod construction_cases;

const VERIFIED_ENUM: &str = "VerifiedEnrollmentSession";
const ENUM_VARIANTS: [&str; 3] = ["MacOs", "Linux", "Verified"];
const SESSION_FILE: &str = "session/mod.rs";
const PARTS_FILE: &str = "src/session/parts.rs";
const VERIFIER_FILE: &str = "untrusted_writer_endpoint_handoff.rs";
const LINUX_VERIFIER_FILE: &str = "session/linux_verifier.rs";
const LINUX_ENTRY_FILE: &str = "session/linux_entry.rs";
const LIB_FILE: &str = "src/lib.rs";

pub(super) fn construction_violations(source: &str, origin: &str) -> Vec<String> {
    let file = syn::parse_file(source).unwrap();
    let mut audit = ConstructionAudit {
        origin,
        impl_stack: Vec::new(),
        fn_stack: Vec::new(),
        pattern_depth: 0,
        violations: Vec::new(),
    };
    audit.visit_file(&file);
    audit.violations
}

struct ConstructionAudit<'a> {
    origin: &'a str,
    impl_stack: Vec<String>,
    fn_stack: Vec<String>,
    pattern_depth: usize,
    violations: Vec<String>,
}

impl ConstructionAudit<'_> {
    fn in_file(&self, suffix: &str) -> bool {
        self.origin.ends_with(suffix)
    }

    fn record(&mut self, detail: &str) {
        self.violations.push(format!("{}: {detail}", self.origin));
    }

    fn struct_literal_is_reviewed(&self, target: &str) -> bool {
        match target {
            SESSION => self.in_file(SESSION_FILE) && self.current_fn() == Some("mint"),
            CLAIM | EFFECT => self.in_file(PARTS_FILE) && self.current_fn() == Some("from_split"),
            _ => true,
        }
    }

    fn current_fn(&self) -> Option<&str> {
        self.fn_stack.last().map(String::as_str)
    }

    fn variant_use_is_reviewed(&self) -> bool {
        self.in_file(VERIFIER_FILE)
            || (self.in_file(LINUX_VERIFIER_FILE)
                && self.current_fn() == Some("authenticate_linux_writer_session"))
    }
}

impl<'ast> Visit<'ast> for ConstructionAudit<'_> {
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let self_type = match &*node.self_ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        };
        self.impl_stack.push(self_type);
        visit::visit_item_impl(self, node);
        self.impl_stack.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !is_test_only(&node.attrs) {
            self.fn_stack.push(node.sig.ident.to_string());
            visit::visit_item_fn(self, node);
            self.fn_stack.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !is_test_only(&node.attrs) {
            self.fn_stack.push(node.sig.ident.to_string());
            visit::visit_impl_item_fn(self, node);
            self.fn_stack.pop();
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !is_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        self.pattern_depth += 1;
        visit::visit_pat(self, node);
        self.pattern_depth -= 1;
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if mentions_guarded_type(node.mac.tokens.clone()) {
            self.record("macro names a guarded authority type");
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if mentions_guarded_type(node.tokens.clone()) {
            self.record("macro names a guarded authority type");
        }
    }

    fn visit_use_tree(&mut self, node: &'ast UseTree) {
        let binding = match node {
            UseTree::Name(name) => Some((name.ident.to_string(), false)),
            UseTree::Rename(rename) => Some((rename.ident.to_string(), true)),
            UseTree::Path(path) if path.ident == VERIFIED_ENUM => {
                self.record("unreviewed path import of the verified-session enum");
                None
            }
            UseTree::Path(_) | UseTree::Glob(_) | UseTree::Group(_) => None,
        };
        if let Some((ident, renamed)) = binding {
            let reviewed = match ident.as_str() {
                SESSION => {
                    !renamed
                        && (self.in_file(LIB_FILE)
                            || self.in_file(LINUX_VERIFIER_FILE)
                            || self.in_file(LINUX_ENTRY_FILE))
                }
                CLAIM | EFFECT => !renamed,
                VERIFIED_ENUM => false,
                name if ENUM_VARIANTS.contains(&name) => false,
                _ => true,
            };
            if !reviewed {
                self.record("unreviewed import of a guarded authority name");
            }
        }
        visit::visit_use_tree(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        let target = match node.path.segments.last() {
            Some(segment) if segment.ident == "Self" && node.path.segments.len() == 1 => {
                self.impl_stack.last().cloned()
            }
            Some(segment) => Some(segment.ident.to_string()),
            None => None,
        };
        if self.pattern_depth == 0
            && target
                .as_deref()
                .is_some_and(|target| !self.struct_literal_is_reviewed(target))
        {
            self.record("unreviewed struct literal of a guarded authority type");
        }
        visit::visit_expr_struct(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(callee) = &*node.func
            && is_enum_variant_path(&callee.path)
            && !self.variant_use_is_reviewed()
        {
            self.record("unreviewed construction of a verified-session variant");
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if self.pattern_depth == 0
            && is_enum_variant_path(&node.path)
            && !self.variant_use_is_reviewed()
        {
            self.record("unreviewed use of a verified-session variant as a value");
        }
        visit::visit_expr_path(self, node);
    }
}

fn is_enum_variant_path(path: &syn::Path) -> bool {
    path.segments.len() >= 2
        && path
            .segments
            .last()
            .is_some_and(|segment| ENUM_VARIANTS.contains(&segment.ident.to_string().as_str()))
}

fn mentions_guarded_type(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => {
            matches!(
                identifier.to_string().as_str(),
                SESSION | CLAIM | EFFECT | VERIFIED_ENUM
            )
        }
        proc_macro2::TokenTree::Group(group) => mentions_guarded_type(group.stream()),
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

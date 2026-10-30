use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, Ident, Macro, UseTree};

use super::{
    BROKER, PERSISTENT_REFERENCE_PROBE, PROVIDER_CREDENTIAL, RAW_RECEIVER_IDENTIFIERS, TASK_RUN,
    TUI_STDIN_SURFACES,
};
use crate::source_reference_audit::{
    include_reference_violation, macro_token_source_reference_violation, path_attribute_violation,
};
use crate::source_tree_helpers::{path_is, pinned_observe_is_reviewed};

#[derive(Default)]
pub(super) struct SurfaceCounts {
    pub(super) stdin: usize,
    pub(super) authority_receive: usize,
    pub(super) pinned_observe: usize,
    pub(super) probe_output_channel: usize,
}

pub(super) struct SourceVisitor<'a> {
    pub(super) root: &'a std::path::Path,
    pub(super) relative: &'a str,
    pub(super) counts: &'a mut SurfaceCounts,
    pub(super) violations: &'a mut Vec<String>,
}

impl SourceVisitor<'_> {
    fn reject(&mut self, surface: &str) {
        self.violations
            .push(format!("{} contains forbidden {surface}", self.relative));
    }
}

impl<'ast> Visit<'ast> for SourceVisitor<'_> {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if let Some(violation) = path_attribute_violation(node, self.root, self.relative) {
            self.reject(&violation);
        }
        visit::visit_attribute(self, node);
    }

    fn visit_ident(&mut self, identifier: &'ast Ident) {
        if RAW_RECEIVER_IDENTIFIERS
            .iter()
            .any(|forbidden| identifier == forbidden)
            || identifier == "observe_current_pinned_writer_session"
        {
            self.reject(&identifier.to_string());
        }
    }

    fn visit_expr_path(&mut self, expression: &'ast ExprPath) {
        let last = expression.path.segments.last().map(|part| &part.ident);
        if last.is_some_and(|identifier| identifier == "stdin") {
            self.reject("stdin identifier outside a reviewed call");
        }
        if last.is_some_and(|identifier| identifier == "receive_from_stdin") {
            self.reject("receive_from_stdin identifier outside a reviewed call");
        }
        if last.is_some_and(|identifier| identifier == "observe_current_pinned_writer_session") {
            self.reject("observe_current_pinned_writer_session identifier outside a reviewed call");
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        let Expr::Path(function) = call.func.as_ref() else {
            visit::visit_expr_call(self, call);
            return;
        };
        let last = function.path.segments.last().map(|part| &part.ident);
        if last.is_some_and(|identifier| identifier == "stdin") {
            if self.relative == PROVIDER_CREDENTIAL
                && call.args.is_empty()
                && path_is(&function.path, &["std", "io", "stdin"])
            {
                self.counts.stdin += 1;
            } else if self.relative == PERSISTENT_REFERENCE_PROBE
                && call.args.is_empty()
                && path_is(&function.path, &["std", "io", "stdin"])
            {
                self.counts.probe_output_channel += 1;
            } else if self.relative == TASK_RUN
                && call.args.is_empty()
                && path_is(&function.path, &["std", "io", "stdin"])
            {
                self.counts.stdin += 1;
            } else if TUI_STDIN_SURFACES.contains(&self.relative)
                && call.args.is_empty()
                && path_is(&function.path, &["std", "io", "stdin"])
            {
                self.counts.stdin += 1;
            } else {
                self.reject("stdin call path");
            }
            visit_call_arguments(self, call);
            return;
        }
        if last.is_some_and(|identifier| identifier == "receive_from_stdin") {
            let expected = [
                "runne_native_enrollment_authority",
                "UntrustedProviderCredentialWriterEndpointHandoffV1",
                "receive_from_stdin",
            ];
            if self.relative == BROKER && call.args.is_empty() && path_is(&function.path, &expected)
            {
                self.counts.authority_receive += 1;
            } else {
                self.reject("receive_from_stdin call path");
            }
            visit_call_arguments(self, call);
            return;
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method != "observe_current_pinned_writer_session" {
            visit::visit_expr_method_call(self, call);
            return;
        }
        if pinned_observe_is_reviewed(self.relative, call, BROKER) {
            self.counts.pinned_observe += 1;
            self.visit_expr(&call.receiver);
            return;
        }
        self.reject("observe_current_pinned_writer_session call path");
        visit::visit_expr_method_call(self, call);
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        let imported = match tree {
            UseTree::Name(name) => Some(&name.ident),
            UseTree::Rename(rename) => Some(&rename.ident),
            _ => None,
        };
        if imported.is_some_and(|identifier| identifier == "stdin") {
            self.reject("stdin import or alias");
        }
        if imported.is_some_and(|identifier| identifier == "receive_from_stdin") {
            self.reject("receive_from_stdin import or alias");
        }
        if imported.is_some_and(|identifier| identifier == "observe_current_pinned_writer_session")
        {
            self.reject("observe_current_pinned_writer_session import or alias");
        }
        visit::visit_use_tree(self, tree);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if node.path.is_ident("macro_rules") {
            self.reject("macro_rules definition");
        }
        if let Some(violation) = include_reference_violation(node) {
            self.reject(&violation);
        }
        if let Some(violation) = macro_token_source_reference_violation(node.tokens.clone()) {
            self.reject(&violation);
        }
        for identifier in super::macro_identifiers(node.tokens.clone()) {
            if identifier == "stdin" && self.relative == "tui_backend/pty_fixture.rs" {
                // The PTY fixture asserts that a real terminal is attached; it
                // is compiled only under `cfg(test)`.
                continue;
            }
            if RAW_RECEIVER_IDENTIFIERS.contains(&identifier.as_str())
                || identifier == "stdin"
                || identifier == "receive_from_stdin"
                || identifier == "observe_current_pinned_writer_session"
            {
                self.reject(&format!("{identifier} macro token"));
            }
        }
        visit::visit_macro(self, node);
    }
}

fn visit_call_arguments(visitor: &mut SourceVisitor<'_>, call: &ExprCall) {
    for argument in &call.args {
        visitor.visit_expr(argument);
    }
}

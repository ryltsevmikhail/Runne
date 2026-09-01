use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ExprCall, ExprPath, File, Ident, Macro, UseTree};

use super::source_reference_audit::{
    include_reference_violation, macro_token_source_reference_violation, path_attribute_violation,
};

const PROVIDER_CREDENTIAL: &str = "cli/provider_credential.rs";
const BROKER: &str = "cli/provider_credential_broker.rs";
const RAW_RECEIVER_IDENTIFIERS: &[&str] = &[
    "recvmsg",
    "RecvMsg",
    "RecvAncillary",
    "RecvAncillaryBuffer",
    "RecvAncillaryMessage",
    "SCM_RIGHTS",
    "ScmRights",
    "SocketAncillary",
    "from_raw_fd",
    "borrow_raw",
    "STDIN_FILENO",
];

pub fn source_tree_violations(root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let mut violations = Vec::new();
    collect_rust_sources(root, &mut paths, &mut violations);
    paths.sort();
    let mut counts = SurfaceCounts::default();
    for path in paths {
        audit_file(root, &path, &mut counts, &mut violations);
    }
    if counts.stdin != 2 {
        violations.push(format!(
            "expected exactly two reviewed std::io::stdin paths, found {}",
            counts.stdin
        ));
    }
    if counts.authority_receive != 1 {
        violations.push(format!(
            "expected exactly one authority receive_from_stdin path, found {}",
            counts.authority_receive
        ));
    }
    violations
}

fn collect_rust_sources(root: &Path, paths: &mut Vec<PathBuf>, violations: &mut Vec<String>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            violations.push(format!("cannot scan {}: {error}", root.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                violations.push(format!("cannot read source entry: {error}"));
                continue;
            }
        };
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                violations.push(format!("cannot inspect {}: {error}", path.display()));
                continue;
            }
        };
        if kind.is_symlink() {
            violations.push(format!(
                "symbolic link source is forbidden: {}",
                path.display()
            ));
        } else if kind.is_dir() {
            collect_rust_sources(&path, paths, violations);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "rs" || extension == "inc")
        {
            paths.push(path);
        }
    }
}

fn audit_file(root: &Path, path: &Path, counts: &mut SurfaceCounts, violations: &mut Vec<String>) {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("cannot read {relative}: {error}"));
            return;
        }
    };
    if path.extension().is_some_and(|extension| extension == "inc") {
        audit_included_tokens(&relative, &source, violations);
        return;
    }
    let file: File = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => {
            violations.push(format!("cannot parse {relative}: {error}"));
            return;
        }
    };
    SourceVisitor {
        relative: &relative,
        counts,
        violations,
    }
    .visit_file(&file);
}

fn audit_included_tokens(relative: &str, source: &str, violations: &mut Vec<String>) {
    let tokens = match source.parse::<proc_macro2::TokenStream>() {
        Ok(tokens) => tokens,
        Err(error) => {
            violations.push(format!("cannot tokenize {relative}: {error}"));
            return;
        }
    };
    for identifier in macro_identifiers(tokens) {
        if RAW_RECEIVER_IDENTIFIERS.contains(&identifier.as_str())
            || identifier == "stdin"
            || identifier == "receive_from_stdin"
            || identifier == "include"
            || identifier == "path"
        {
            violations.push(format!("{relative} contains forbidden {identifier}"));
        }
    }
}

#[derive(Default)]
struct SurfaceCounts {
    stdin: usize,
    authority_receive: usize,
}

struct SourceVisitor<'a> {
    relative: &'a str,
    counts: &'a mut SurfaceCounts,
    violations: &'a mut Vec<String>,
}

impl SourceVisitor<'_> {
    fn reject(&mut self, surface: &str) {
        self.violations
            .push(format!("{} contains forbidden {surface}", self.relative));
    }
}

impl<'ast> Visit<'ast> for SourceVisitor<'_> {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if let Some(violation) = path_attribute_violation(node) {
            self.reject(&violation);
        }
        visit::visit_attribute(self, node);
    }

    fn visit_ident(&mut self, identifier: &'ast Ident) {
        if RAW_RECEIVER_IDENTIFIERS
            .iter()
            .any(|forbidden| identifier == forbidden)
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
        for identifier in macro_identifiers(node.tokens.clone()) {
            if RAW_RECEIVER_IDENTIFIERS.contains(&identifier.as_str())
                || identifier == "stdin"
                || identifier == "receive_from_stdin"
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

fn path_is(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected && segment.arguments.is_empty())
}

fn macro_identifiers(tokens: proc_macro2::TokenStream) -> Vec<String> {
    let mut identifiers = Vec::new();
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(identifier) => {
                identifiers.push(identifier.to_string());
            }
            proc_macro2::TokenTree::Group(group) => {
                identifiers.extend(macro_identifiers(group.stream()));
            }
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
    identifiers
}

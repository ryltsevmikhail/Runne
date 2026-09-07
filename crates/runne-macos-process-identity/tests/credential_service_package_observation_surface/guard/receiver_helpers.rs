use std::collections::HashSet;

use super::calls::{TargetMethod, expr_path_target_method};
use syn::{Expr, Pat, UseTree};

pub(super) fn ident_pattern(ident: &syn::Ident) -> Pat {
    Pat::Ident(syn::PatIdent {
        attrs: Vec::new(),
        by_ref: None,
        mutability: None,
        ident: ident.clone(),
        subpat: None,
    })
}

pub(super) fn collect_function_use_tree(
    tree: &UseTree,
    prefix: &[String],
    known: &HashSet<String>,
    capture: &mut HashSet<String>,
    verify: &mut HashSet<String>,
) {
    match tree {
        UseTree::Group(group) => group.items.iter().for_each(|item| {
            collect_function_use_tree(item, prefix, known, capture, verify);
        }),
        UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            collect_function_use_tree(&path.tree, &next, known, capture, verify);
        }
        UseTree::Name(name) => add_function_alias(
            prefix,
            &name.ident.to_string(),
            &name.ident,
            known,
            capture,
            verify,
        ),
        UseTree::Rename(rename) => add_function_alias(
            prefix,
            &rename.ident.to_string(),
            &rename.rename,
            known,
            capture,
            verify,
        ),
        UseTree::Glob(_) => {}
    }
}

fn add_function_alias(
    prefix: &[String],
    source: &str,
    local: &syn::Ident,
    known: &HashSet<String>,
    capture: &mut HashSet<String>,
    verify: &mut HashSet<String>,
) {
    if !prefix.iter().any(|part| known.contains(part)) {
        return;
    }
    match source {
        "capture_current" => {
            capture.insert(local.to_string());
        }
        "verify_exact" => {
            verify.insert(local.to_string());
        }
        _ => {}
    }
}

pub(super) fn collect_pattern_names(pattern: &Pat, names: &mut HashSet<String>) {
    match pattern {
        Pat::Ident(pattern) => {
            names.insert(pattern.ident.to_string());
        }
        Pat::Paren(pattern) => collect_pattern_names(&pattern.pat, names),
        Pat::Reference(pattern) => collect_pattern_names(&pattern.pat, names),
        Pat::Tuple(pattern) => pattern
            .elems
            .iter()
            .for_each(|item| collect_pattern_names(item, names)),
        Pat::TupleStruct(pattern) => pattern
            .elems
            .iter()
            .for_each(|item| collect_pattern_names(item, names)),
        Pat::Struct(pattern) => pattern
            .fields
            .iter()
            .for_each(|field| collect_pattern_names(&field.pat, names)),
        Pat::Type(pattern) => collect_pattern_names(&pattern.pat, names),
        _ => {}
    }
}

pub(super) fn expression_produces_target(
    expression: &Expr,
    known: &HashSet<String>,
    capture: &HashSet<String>,
    verify: &HashSet<String>,
) -> bool {
    match expression {
        Expr::Call(call) => {
            called_target_method(call.func.as_ref(), known, capture, verify)
                == Some(TargetMethod::Capture)
        }
        Expr::Group(group) => expression_produces_target(&group.expr, known, capture, verify),
        Expr::Paren(paren) => expression_produces_target(&paren.expr, known, capture, verify),
        Expr::Reference(reference) => {
            expression_produces_target(&reference.expr, known, capture, verify)
        }
        Expr::Cast(cast) => expression_produces_target(&cast.expr, known, capture, verify),
        Expr::Try(expression) => {
            expression_produces_target(&expression.expr, known, capture, verify)
        }
        _ => false,
    }
}

pub(super) fn called_target_method(
    expression: &Expr,
    known: &HashSet<String>,
    capture: &HashSet<String>,
    verify: &HashSet<String>,
) -> Option<TargetMethod> {
    match expression {
        Expr::Path(path) => {
            let name = path.path.segments.last()?.ident.to_string();
            if capture.contains(&name) {
                Some(TargetMethod::Capture)
            } else if verify.contains(&name) {
                Some(TargetMethod::Verify)
            } else {
                expr_path_target_method(path, known)
            }
        }
        Expr::Group(group) => called_target_method(&group.expr, known, capture, verify),
        Expr::Paren(paren) => called_target_method(&paren.expr, known, capture, verify),
        Expr::Reference(reference) => called_target_method(&reference.expr, known, capture, verify),
        Expr::Cast(cast) => called_target_method(&cast.expr, known, capture, verify),
        _ => None,
    }
}

pub(super) fn target_function_item(
    expression: &Expr,
    known: &HashSet<String>,
    capture: &HashSet<String>,
    verify: &HashSet<String>,
) -> Option<TargetMethod> {
    match expression {
        Expr::Path(path) => {
            let name = path.path.segments.last()?.ident.to_string();
            if capture.contains(&name) {
                Some(TargetMethod::Capture)
            } else if verify.contains(&name) {
                Some(TargetMethod::Verify)
            } else {
                expr_path_target_method(path, known)
            }
        }
        Expr::Group(group) => target_function_item(&group.expr, known, capture, verify),
        Expr::Paren(paren) => target_function_item(&paren.expr, known, capture, verify),
        Expr::Reference(reference) => target_function_item(&reference.expr, known, capture, verify),
        Expr::Cast(cast) => target_function_item(&cast.expr, known, capture, verify),
        _ => None,
    }
}

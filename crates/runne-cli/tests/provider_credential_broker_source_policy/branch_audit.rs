use syn::{Attribute, Block, Expr, Item, Meta, Stmt};

#[path = "branch_audit/core_flow.rs"]
mod core_flow;
#[path = "branch_audit/secret.rs"]
mod secret;
#[path = "branch_audit/stages.rs"]
mod stages;

use core_flow::{
    is_exact_linux_block, is_exact_non_macos_block, is_handoff_local, is_pinned_local,
    is_runner_tail,
};
use secret::is_secret_local;
use stages::Stage;

pub fn broker_branch_violations(source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => return vec![format!("broker source does not parse: {error}")],
    };
    let functions: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "run_provider_credential_broker" => {
                Some(function)
            }
            _ => None,
        })
        .collect();
    if functions.len() != 1 {
        return vec![format!(
            "expected one run_provider_credential_broker, found {}",
            functions.len()
        )];
    }
    let function = functions[0];
    let mut violations = Vec::new();
    if !matches!(function.vis, syn::Visibility::Inherited) {
        violations.push("broker entry point must remain private".to_owned());
    }
    if function.block.stmts.len() != 5 {
        violations.push(
            "broker must contain exactly two argv gates and three platform branches".to_owned(),
        );
        return violations;
    }
    if !is_expect_token(&function.block.stmts[0]) {
        violations.push("broker must first validate the fixed mode token".to_owned());
    }
    if !is_expect_end(&function.block.stmts[1]) {
        violations.push("broker must validate argv end before either platform branch".to_owned());
    }
    match cfg_block(&function.block.stmts[2], CfgKind::MacOs) {
        Some(block) if is_exact_macos_block(block) => {}
        _ => {
            violations.push(
                "macOS branch must detect fd 3, pin the handoff, then run that exact pair"
                    .to_owned(),
            );
        }
    }
    match cfg_block(&function.block.stmts[3], CfgKind::Linux) {
        Some(block) if is_exact_linux_block(block) => {}
        _ => violations.push(
            "linux branch must validate the pipe, sweep, and respond with the exact secret"
                .to_owned(),
        ),
    }
    match cfg_block(&function.block.stmts[4], CfgKind::NotMacOsLinux) {
        Some(block) if is_exact_non_macos_block(block) => {}
        _ => {
            violations.push("non-macOS/Linux branch must only return typed unsupported".to_owned());
        }
    }
    violations
}

fn is_expect_token(statement: &Stmt) -> bool {
    let Some(call) = tried_call(statement, "expect_token") else {
        return false;
    };
    call.args.len() == 2
        && is_reference_to(&call.args[0], "arguments", true)
        && is_path(&call.args[1], &["PROVIDER_CREDENTIAL_BROKER_MODE_V1"])
}

fn is_expect_end(statement: &Stmt) -> bool {
    let Some(call) = tried_call(statement, "expect_end") else {
        return false;
    };
    call.args.len() == 1 && is_reference_to(&call.args[0], "arguments", false)
}

fn tried_call<'a>(statement: &'a Stmt, function: &str) -> Option<&'a syn::ExprCall> {
    let Stmt::Expr(Expr::Try(tried), Some(_)) = statement else {
        return None;
    };
    let Expr::Call(call) = tried.expr.as_ref() else {
        return None;
    };
    (tried.attrs.is_empty() && call.attrs.is_empty() && is_path(call.func.as_ref(), &[function]))
        .then_some(call)
}

fn is_reference_to(expression: &Expr, name: &str, mutable: bool) -> bool {
    let Expr::Reference(reference) = expression else {
        return false;
    };
    reference.attrs.is_empty()
        && reference.mutability.is_some() == mutable
        && is_path(reference.expr.as_ref(), &[name])
}

#[derive(Clone, Copy)]
enum CfgKind {
    MacOs,
    Linux,
    NotMacOsLinux,
}

fn cfg_block(statement: &Stmt, expected: CfgKind) -> Option<&Block> {
    let Stmt::Expr(Expr::Block(block), None) = statement else {
        return None;
    };
    (block.label.is_none() && block.attrs.len() == 1 && cfg_matches(&block.attrs[0], expected))
        .then_some(&block.block)
}

fn cfg_matches(attribute: &Attribute, expected: CfgKind) -> bool {
    let Meta::List(cfg) = &attribute.meta else {
        return false;
    };
    if !cfg.path.is_ident("cfg") {
        return false;
    }
    let Ok(meta) = syn::parse2::<Meta>(cfg.tokens.clone()) else {
        return false;
    };
    match expected {
        CfgKind::MacOs => is_target_os(&meta, "macos"),
        CfgKind::Linux => is_target_os(&meta, "linux"),
        CfgKind::NotMacOsLinux => is_not_any_macos_linux(&meta),
    }
}

fn is_target_os(meta: &Meta, os: &str) -> bool {
    let Meta::NameValue(value) = meta else {
        return false;
    };
    if !value.path.is_ident("target_os") {
        return false;
    }
    matches!(
        &value.value,
        Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Str(value) if value.value() == os)
    )
}

/// Matches exactly `not(any(target_os = "macos", target_os = "linux"))`.
///
/// Token-level normalization: whitespace inside the token stream is not
/// significant, so it is stripped before the canonical comparison.
fn is_not_any_macos_linux(meta: &Meta) -> bool {
    let Meta::List(not) = meta else {
        return false;
    };
    if !not.path.is_ident("not") {
        return false;
    }
    let rendered = not
        .tokens
        .to_string()
        .split_whitespace()
        .collect::<String>();
    rendered == "any(target_os=\"macos\",target_os=\"linux\")"
}

/// The macOS branch keeps its exact audited core flow while each step is
/// wrapped in its fixed stage marker and reviewed failed-stage adapter:
/// eight statements, strictly alternating marker and core step.
fn is_exact_macos_block(block: &Block) -> bool {
    block.stmts.len() == 8
        && stages::is_stage_marker(&block.stmts[0], Stage::SecretInspect)
        && is_secret_local(&block.stmts[1])
        && stages::is_stage_marker(&block.stmts[2], Stage::EndpointReceive)
        && is_handoff_local(&block.stmts[3])
        && stages::is_stage_marker(&block.stmts[4], Stage::SessionObserve)
        && is_pinned_local(&block.stmts[5])
        && stages::is_stage_marker(&block.stmts[6], Stage::AuthenticatedRun)
        && is_runner_tail(&block.stmts[7])
}

fn is_path(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = expression else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected && segment.arguments.is_empty())
}

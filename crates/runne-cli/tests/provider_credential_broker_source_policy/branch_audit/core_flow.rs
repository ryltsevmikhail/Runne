//! Exact core-flow predicates for the macOS broker branch. Each local keeps
//! its historical strict shape; the only permitted addition is one reviewed
//! failed-stage `inspect_err` adapter, unwrapped through `stages`.

use syn::{Block, Expr, Pat, Stmt};

use super::stages::{self, Stage, StageAdapter};

pub fn is_handoff_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "handoff"
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
    {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some() {
        return false;
    }
    let Expr::Try(tried) = initializer.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(map_error_call) = tried.expr.as_ref() else {
        return false;
    };
    if !tried.attrs.is_empty()
        || !map_error_call.attrs.is_empty()
        || map_error_call.method != "map_err"
        || map_error_call.turbofish.is_some()
        || map_error_call.args.len() != 1
    {
        return false;
    }
    let StageAdapter::Reviewed(inner) =
        stages::failed_stage_adapter(map_error_call.receiver.as_ref(), Stage::EndpointReceive)
    else {
        return false;
    };
    let Expr::Call(receive) = inner else {
        return false;
    };
    let receive_path = [
        "runne_native_enrollment_authority",
        "UntrustedProviderCredentialWriterEndpointHandoffV1",
        "receive_from_stdin",
    ];
    if !receive.attrs.is_empty() || !receive.args.is_empty() {
        return false;
    }
    if !is_path(receive.func.as_ref(), &receive_path) {
        return false;
    }
    let Some(Expr::Closure(error_mapper)) = map_error_call.args.first() else {
        return false;
    };
    error_mapper.attrs.is_empty()
        && error_mapper.inputs.len() == 1
        && matches!(error_mapper.inputs.first(), Some(Pat::Wild(_)))
        && is_path(
            error_mapper.body.as_ref(),
            &["CliError", "CredentialOperation"],
        )
}

pub fn is_pinned_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "pinned"
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
    {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some() {
        return false;
    }
    let Expr::Try(tried) = initializer.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(map_error_call) = tried.expr.as_ref() else {
        return false;
    };
    let StageAdapter::Reviewed(inner) =
        stages::failed_stage_adapter(map_error_call.receiver.as_ref(), Stage::SessionObserve)
    else {
        return false;
    };
    let Expr::MethodCall(observe) = inner else {
        return false;
    };
    tried.attrs.is_empty()
        && map_error_call.attrs.is_empty()
        && map_error_call.method == "map_err"
        && map_error_call.turbofish.is_none()
        && map_error_call.args.len() == 1
        && observe.attrs.is_empty()
        && observe.method == "observe_current_pinned_writer_session"
        && observe.turbofish.is_none()
        && observe.args.is_empty()
        && is_path(observe.receiver.as_ref(), &["handoff"])
        && matches!(map_error_call.args.first(), Some(Expr::Closure(error_mapper))
            if error_mapper.attrs.is_empty()
                && error_mapper.inputs.len() == 1
                && matches!(error_mapper.inputs.first(), Some(Pat::Wild(_)))
                && is_path(error_mapper.body.as_ref(), &["CliError", "CredentialOperation"]))
}

/// The tail `run::run_authenticated_writer(pinned, secret)` result, allowed
/// to be wrapped in exactly one reviewed authenticated-run failed adapter.
pub fn is_runner_tail(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::MethodCall(adapter), None) = statement else {
        return false;
    };
    if adapter.method != "inspect_err"
        || adapter.turbofish.is_some()
        || !adapter.attrs.is_empty()
        || adapter.args.len() != 1
    {
        return false;
    }
    let Some(Expr::Closure(closure)) = adapter.args.first() else {
        return false;
    };
    if !is_reviewed_run_failure_closure(closure) {
        return false;
    }
    let Expr::Call(call) = adapter.receiver.as_ref() else {
        return false;
    };
    call.attrs.is_empty()
        && call.args.len() == 2
        && is_path(call.func.as_ref(), &["run", "run_authenticated_writer"])
        && is_path(&call.args[0], &["pinned"])
        && is_path(&call.args[1], &["secret"])
}

fn is_reviewed_run_failure_closure(closure: &syn::ExprClosure) -> bool {
    if !closure.attrs.is_empty() || closure.inputs.len() != 1 {
        return false;
    }
    if !matches!(closure.inputs.first(), Some(Pat::Wild(_))) {
        return false;
    }
    let Expr::Call(body) = closure.body.as_ref() else {
        return false;
    };
    body.attrs.is_empty()
        && body.args.is_empty()
        && is_path(
            body.func.as_ref(),
            &["writer_stage", "authenticated_run_failed"],
        )
}

pub fn is_exact_non_macos_block(block: &Block) -> bool {
    block.stmts.len() == 1 && is_error(&block.stmts[0], "UnsupportedCredentialBackend")
}

fn is_error(statement: &Stmt, variant: &str) -> bool {
    let Stmt::Expr(Expr::Call(call), None) = statement else {
        return false;
    };
    call.attrs.is_empty()
        && call.args.len() == 1
        && is_path(call.func.as_ref(), &["Err"])
        && is_path(&call.args[0], &["CliError", variant])
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

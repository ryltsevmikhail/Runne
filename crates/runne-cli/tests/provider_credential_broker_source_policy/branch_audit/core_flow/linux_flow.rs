use syn::{Block, Expr, Pat, Stmt};

use super::is_path;

/// The Linux branch validates the inherited secret-pipe shape, sweeps every
/// other inherited descriptor before any authentication, and hands the exact
/// retained secret to the startup responder: four statements, no ingress.
pub fn is_exact_linux_block(block: &Block) -> bool {
    is_linux_pipe_local(&block.stmts[0])
        && is_linux_retained_local(&block.stmts[1])
        && is_linux_sweep_statement(&block.stmts[2])
        && is_linux_responder_tail(&block.stmts[3])
}

fn is_linux_pipe_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "secret"
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
    if !tried.attrs.is_empty() {
        return false;
    }
    let Expr::Call(inspect) = tried.expr.as_ref() else {
        return false;
    };
    inspect.attrs.is_empty()
        && inspect.args.is_empty()
        && is_path(
            inspect.func.as_ref(),
            &["channel", "InheritedSecretInputSlot", "inspect"],
        )
}

fn is_linux_retained_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.ident != "retained"
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
    if !tried.attrs.is_empty() {
        return false;
    }
    let Expr::MethodCall(validate) = tried.expr.as_ref() else {
        return false;
    };
    validate.attrs.is_empty()
        && validate.method == "validated_descriptor_for_sweep"
        && validate.turbofish.is_none()
        && validate.args.is_empty()
        && is_path(validate.receiver.as_ref(), &["secret"])
}

fn is_linux_sweep_statement(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::Try(tried), Some(_)) = statement else {
        return false;
    };
    if !tried.attrs.is_empty() {
        return false;
    }
    let Expr::MethodCall(map_error) = tried.expr.as_ref() else {
        return false;
    };
    if !map_error.attrs.is_empty()
        || map_error.method != "map_err"
        || map_error.turbofish.is_some()
        || map_error.args.len() != 1
    {
        return false;
    }
    let Expr::Call(sweep) = map_error.receiver.as_ref() else {
        return false;
    };
    if !sweep.attrs.is_empty()
        || sweep.args.len() != 2
        || !is_path(
            sweep.func.as_ref(),
            &["writer_fd_sweep", "close_inherited_descriptors_except"],
        )
        || !is_path(&sweep.args[0], &["writer_fd_sweep", "enumerate_proc_fds"])
        || !is_path(&sweep.args[1], &["retained"])
    {
        return false;
    }
    let Expr::Closure(deny) = &map_error.args[0] else {
        return false;
    };
    deny.asyncness.is_none()
        && deny.capture.is_none()
        && deny.inputs.len() == 1
        && matches!(deny.inputs.first(), Some(Pat::Wild(_)))
        && is_path(deny.body.as_ref(), &["CliError", "CredentialOperation"])
}

fn is_linux_responder_tail(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::Call(call), None) = statement else {
        return false;
    };
    call.attrs.is_empty()
        && call.args.len() == 1
        && is_path(
            call.func.as_ref(),
            &["writer_handshake", "respond_startup_from_stdout"],
        )
        && is_path(&call.args[0], &["secret"])
}

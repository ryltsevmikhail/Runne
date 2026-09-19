use syn::{Expr, Pat, Stmt};

use super::stages::{self, Stage, StageAdapter};

pub fn is_secret_local(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    let Pat::Ident(binding) = &local.pat else {
        return false;
    };
    let Some(initializer) = &local.init else {
        return false;
    };
    let Expr::Try(tried) = initializer.expr.as_ref() else {
        return false;
    };
    let Expr::MethodCall(mapped) = tried.expr.as_ref() else {
        return false;
    };
    let StageAdapter::Reviewed(inner) =
        stages::failed_stage_adapter(mapped.receiver.as_ref(), Stage::SecretInspect)
    else {
        return false;
    };
    let Expr::Call(inspect) = inner else {
        return false;
    };
    binding.ident == "secret"
        && mapped.method == "map_err"
        && mapped.args.len() == 1
        && inspect.args.is_empty()
        && path_is(
            inspect.func.as_ref(),
            &["channel", "InheritedSecretInputSlot", "inspect"],
        )
        && matches!(mapped.args.first(), Some(Expr::Closure(conversion))
            if conversion.inputs.len() == 1
                && matches!(conversion.inputs.first(), Some(Pat::Wild(_)))
                && path_is(conversion.body.as_ref(), &["CliError", "CredentialOperation"]))
}

fn path_is(expression: &Expr, expected: &[&str]) -> bool {
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

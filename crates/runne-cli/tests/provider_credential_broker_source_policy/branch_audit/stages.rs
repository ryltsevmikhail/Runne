//! Recognizes the audited writer startup stage reporting that may surround
//! the exact macOS broker flow: fixed-vocabulary marker calls and the
//! matching `inspect_err` failed-stage adapters.

use syn::{Expr, ExprClosure, Pat, Stmt};

use crate::source_tree_helpers::path_is;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    SecretInspect,
    EndpointReceive,
    SessionObserve,
    AuthenticatedRun,
}

impl Stage {
    const fn marker(self) -> &'static str {
        match self {
            Self::SecretInspect => "secret_inspect",
            Self::EndpointReceive => "endpoint_receive",
            Self::SessionObserve => "session_observe",
            Self::AuthenticatedRun => "authenticated_run",
        }
    }

    const fn failed_marker(self) -> &'static str {
        match self {
            Self::SecretInspect => "secret_inspect_failed",
            Self::EndpointReceive => "endpoint_receive_failed",
            Self::SessionObserve => "session_observe_failed",
            Self::AuthenticatedRun => "authenticated_run_failed",
        }
    }
}

/// True when the statement is exactly `writer_stage::<stage>();`.
pub fn is_stage_marker(statement: &Stmt, stage: Stage) -> bool {
    let Stmt::Expr(Expr::Call(call), Some(_)) = statement else {
        return false;
    };
    call.attrs.is_empty()
        && call.args.is_empty()
        && path_is_call(call.func.as_ref(), &["writer_stage", stage.marker()])
}

/// Outcome of unwrapping the required `.inspect_err(|_| writer_stage::<stage>_failed())`
/// adapter from an expression.
pub enum StageAdapter<'a> {
    /// Exactly one reviewed failed-stage adapter; carries the inner receiver.
    Reviewed(&'a Expr),
    /// No adapter at all.
    Missing,
    /// An adapter-shaped expression that is not the reviewed stage form.
    Unreviewed,
}

pub fn failed_stage_adapter(expression: &Expr, stage: Stage) -> StageAdapter<'_> {
    let Expr::MethodCall(call) = expression else {
        return StageAdapter::Missing;
    };
    if call.method != "inspect_err"
        || call.turbofish.is_some()
        || !call.attrs.is_empty()
        || call.args.len() != 1
    {
        return StageAdapter::Unreviewed;
    }
    let Some(Expr::Closure(closure)) = call.args.first() else {
        return StageAdapter::Unreviewed;
    };
    if !is_reviewed_failed_marker_closure(closure, stage) {
        return StageAdapter::Unreviewed;
    }
    StageAdapter::Reviewed(call.receiver.as_ref())
}

fn is_reviewed_failed_marker_closure(closure: &ExprClosure, stage: Stage) -> bool {
    if !closure.attrs.is_empty()
        || closure.inputs.len() != 1
        || !matches!(closure.inputs.first(), Some(Pat::Wild(_)))
    {
        return false;
    }
    let Expr::Call(body) = closure.body.as_ref() else {
        return false;
    };
    body.attrs.is_empty()
        && body.args.is_empty()
        && path_is_call(body.func.as_ref(), &["writer_stage", stage.failed_marker()])
}

fn path_is_call(function: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = function else {
        return false;
    };
    path.attrs.is_empty() && path.qself.is_none() && path_is(&path.path, expected)
}

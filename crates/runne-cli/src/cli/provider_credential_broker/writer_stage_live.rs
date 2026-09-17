//! Live writer startup stage diagnostics for the local enrollment fixtures.
//!
//! Security invariant (audited by
//! `tests/provider_credential_broker_source_policy`): every emission here is
//! exactly one fixed string literal from the audited stage vocabulary. The
//! sinks accept no arguments and never format runtime values, so secret
//! material cannot reach stderr through this module.

/// Marks the fd 3 secret-slot inspection stage.
pub fn secret_inspect() {
    eprintln!("writer-stage=secret-inspect");
}

/// Marks the daemon endpoint handoff receive stage.
pub fn endpoint_receive() {
    eprintln!("writer-stage=endpoint-receive");
}

/// Marks the pinned writer session observation stage.
pub fn session_observe() {
    eprintln!("writer-stage=session-observe");
}

/// Marks the authenticated writer execution stage.
pub fn authenticated_run() {
    eprintln!("writer-stage=authenticated-run");
}

/// Reports that the fd 3 secret-slot inspection stage failed.
pub fn secret_inspect_failed() {
    eprintln!("writer-stage-failed=secret-inspect");
}

/// Reports that the daemon endpoint handoff receive stage failed.
pub fn endpoint_receive_failed() {
    eprintln!("writer-stage-failed=endpoint-receive");
}

/// Reports that the pinned writer session observation stage failed.
pub fn session_observe_failed() {
    eprintln!("writer-stage-failed=session-observe");
}

/// Reports that the authenticated writer execution stage failed.
pub fn authenticated_run_failed() {
    eprintln!("writer-stage-failed=authenticated-run");
}

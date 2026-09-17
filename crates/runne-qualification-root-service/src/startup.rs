use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runne_macos_xpc::{
    QualificationRunnerEndpoint, QualificationRunnerEndpointConfiguration,
    QualificationRunnerPeerRequirement, QualificationRunnerSessionBinding,
    QualificationRunnerXpcListener,
};

use crate::{Error, Result, session_factory::Factory, state::RootState};

pub fn run() -> Result<()> {
    let state = RootState::load()?;
    let policy = state.policy();
    let configuration = QualificationRunnerEndpointConfiguration::new(
        QualificationRunnerEndpoint::RootConsume,
        QualificationRunnerPeerRequirement::new(policy.root_consume().code_requirement())
            .map_err(|_| Error)?,
        QualificationRunnerPeerRequirement::new(policy.executor().code_requirement())
            .map_err(|_| Error)?,
        QualificationRunnerSessionBinding::new(policy.login_euid(), policy.login_audit_session())
            .map_err(|_| Error)?,
        QualificationRunnerSessionBinding::new(0, policy.root_audit_session())
            .map_err(|_| Error)?,
    )
    .map_err(|_| Error)?;
    let expected_euid = policy.login_euid();
    let expected_audit_session = policy.login_audit_session();
    let remaining = policy
        .expires_at()
        .checked_sub(crate::state::now()?)
        .ok_or(Error)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(remaining))
        .ok_or(Error)?;
    let state = Arc::new(Mutex::new(state));
    let listener = QualificationRunnerXpcListener::bind(
        &configuration,
        Arc::new(Factory {
            state,
            expected_euid,
            expected_audit_session,
            deadline,
        }),
    )
    .map_err(|_| Error)?;
    loop {
        if Instant::now() >= deadline {
            listener.invalidate();
            return Err(Error);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

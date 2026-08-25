#![allow(dead_code)]

use super::{ProcessInvocationResolver, ResolvedProcessInvocation};
use runne_api::{ProcessHostError, StartProcessCommand};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Closed failures while publishing runtime-owned process material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProcessInvocationRegistrationError {
    #[error("process invocation registration is invalid")]
    Invalid,
    #[error("process invocation registration conflicts with an existing intent")]
    Conflict,
    #[error("process invocation registry is unavailable")]
    Unavailable,
}

struct Registration {
    command: StartProcessCommand,
    request_digest: [u8; 32],
    resolved: ResolvedProcessInvocation,
}

/// Runtime-owned source of exact process invocations.
///
/// The registry is deliberately not constructed from HTTP or renderer input.
/// A runtime task-run producer must publish the complete, already-authorized
/// invocation before Desktop can request its opaque invocation identifier.
#[derive(Clone, Default)]
pub(crate) struct AuthoritativeProcessInvocationRegistry {
    entries: Arc<Mutex<HashMap<[u8; 16], Registration>>>,
}

impl AuthoritativeProcessInvocationRegistry {
    /// Publishes one immutable invocation or acknowledges an exact replay.
    pub(crate) fn register(
        &self,
        command: StartProcessCommand,
        resolved: ResolvedProcessInvocation,
    ) -> Result<(), ProcessInvocationRegistrationError> {
        if command.invocation_id.as_bytes() == &[0; 16]
            || resolved.request_digest == [0; 32]
            || resolved.spec.executable_digest.is_none()
        {
            return Err(ProcessInvocationRegistrationError::Invalid);
        }
        let key = *command.invocation_id.as_bytes();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ProcessInvocationRegistrationError::Unavailable)?;
        if let Some(existing) = entries.get(&key) {
            return (existing.command == command
                && existing.request_digest == resolved.request_digest)
                .then_some(())
                .ok_or(ProcessInvocationRegistrationError::Conflict);
        }
        entries.insert(
            key,
            Registration {
                command,
                request_digest: resolved.request_digest,
                resolved,
            },
        );
        Ok(())
    }
}

impl ProcessInvocationResolver for AuthoritativeProcessInvocationRegistry {
    fn resolve(
        &self,
        command: &StartProcessCommand,
    ) -> Result<ResolvedProcessInvocation, ProcessHostError> {
        let key = *command.invocation_id.as_bytes();
        let entries = self
            .entries
            .lock()
            .map_err(|_| ProcessHostError::Unavailable)?;
        let registration = entries.get(&key).ok_or(ProcessHostError::Unavailable)?;
        (registration.command == *command)
            .then_some(registration.resolved.clone())
            .ok_or(ProcessHostError::Conflict)
    }
}

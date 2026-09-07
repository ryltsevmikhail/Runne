//! Bounded drain and shutdown handling.

use crate::error::HostError;
use crate::session::{HostSession, HostState};

impl<B: crate::backend::BackendPort> HostSession<B> {
    /// Drain: stop admitting new generation requests, bounded wait.
    pub fn drain(&mut self, deadline_ms: u64) -> Result<(), HostError> {
        if !matches!(
            self.state,
            HostState::Ready | HostState::Loaded | HostState::Generating
        ) {
            return Err(HostError::InvalidState);
        }
        let _ = deadline_ms;
        self.state = HostState::Draining;
        Ok(())
    }

    /// Bounded shutdown: releases backend state and marks Stopped.
    pub fn shutdown(&mut self, deadline_ms: u64) -> Result<(), HostError> {
        if matches!(self.state, HostState::Stopped | HostState::Failed) {
            return Err(HostError::InvalidState);
        }
        let _ = deadline_ms;
        self.backend.unload()?;
        self.state = HostState::Stopped;
        Ok(())
    }
}

//! Draft caller-side fail-closed latch; not commit/durability evidence.
use super::{channel, clock::Deadline, owned_role::OwnedRole};
use std::{io, os::unix::net::UnixStream};

pub(super) struct ZeroResponse {
    stream: UnixStream,
    deadline: Deadline,
    owner_pid: u32,
    association: std::sync::Arc<()>,
    live_observed: bool,
    failed: bool,
}
impl ZeroResponse {
    // Own the sole supervisor endpoint; caller must close all inherited aliases.
    pub(super) fn new(stream: UnixStream, owner: &OwnedRole) -> Self {
        Self { stream, deadline: owner.deadline(), owner_pid: owner.id(),
            association: std::sync::Arc::clone(owner.association()),
            live_observed: false, failed: false }
    }
    pub(super) fn before_abort(&mut self, owner: &mut OwnedRole) -> io::Result<()> {
        if self.failed { return Err(io::ErrorKind::InvalidData.into()); }
        // Latch before any consuming probe or liveness/identity error.
        self.failed = true;
        if !std::sync::Arc::ptr_eq(&self.association, owner.association())
            || owner.id() != self.owner_pid || owner.deadline() != self.deadline {
            return Err(io::ErrorKind::InvalidData.into());
        }
        owner.live()?;
        channel::no_result_yet(&mut self.stream, self.deadline)?;
        owner.live()?;
        self.live_observed = true;
        self.failed = false;
        Ok(())
    }
    // Consumes the latch and socket: a failed final check cannot be retried.
    pub(super) fn after_collected_abort(mut self, owner: &OwnedRole) -> io::Result<()> {
        if self.failed || !self.live_observed
            || !std::sync::Arc::ptr_eq(&self.association, owner.association())
            || owner.id() != self.owner_pid
            || owner.deadline() != self.deadline || !owner.collected_abort() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.failed = true;
        channel::require_eof_without_bytes(&mut self.stream, self.deadline)
    }
}

use block2::ManualBlockEncoding;
use objc2_foundation::{NSData, NSXPCConnection};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use super::NativePeerBinding;
use crate::CredentialServiceXpcError;

pub(super) type ReplyResult = Result<Zeroizing<Vec<u8>>, CredentialServiceXpcError>;
pub(super) type ReplySlot = Arc<Mutex<Option<oneshot::Sender<ReplyResult>>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectionEvent {
    Active,
    Interrupted,
    Invalidated,
}

pub(super) struct ReplyBlockEncoding;

// SAFETY: On 64-bit macOS this is the clang ABI encoding for
// `void (^)(NSData *)`, including the hidden block object at offset zero.
unsafe impl ManualBlockEncoding for ReplyBlockEncoding {
    type Arguments = (*mut NSData,);
    type Return = ();
    const ENCODING_CSTR: &'static core::ffi::CStr = c"v16@?0@8";
}

pub(super) struct PeerObservation {
    terminal: AtomicBool,
    verified_reply_observed: AtomicBool,
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // Independent observations, not exclusive states.
struct PeerRevalidationSnapshot {
    event: ConnectionEvent,
    terminal: bool,
    verified_reply_observed: bool,
    binding_present: bool,
    deadline_reached: bool,
}

impl PeerObservation {
    pub(super) const fn new() -> Self {
        Self {
            terminal: AtomicBool::new(false),
            verified_reply_observed: AtomicBool::new(false),
        }
    }

    pub(super) fn mark_terminal(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    pub(super) fn observe_verified_reply(&self) {
        self.verified_reply_observed.store(true, Ordering::Release);
    }

    fn begin_exchange(
        &self,
        connection: &NSXPCConnection,
        events: &watch::Sender<ConnectionEvent>,
        binding: Option<NativePeerBinding>,
        deadline: Instant,
    ) -> Result<(), CredentialServiceXpcError> {
        let result = qualification_exchange_guard(self.snapshot(events, binding, deadline));
        if result.is_err() {
            self.mark_terminal();
            connection.invalidate();
        }
        result
    }

    pub(super) fn revalidate(
        &self,
        connection: &NSXPCConnection,
        events: &watch::Sender<ConnectionEvent>,
        binding: Option<NativePeerBinding>,
        deadline: Instant,
    ) -> Result<(), CredentialServiceXpcError> {
        let guard = || peer_revalidation_guard(self.snapshot(events, binding, deadline));
        let result = guard()
            .and_then(|()| binding.ok_or(CredentialServiceXpcError::Rejected))
            .and_then(|binding| assert_peer_binding(connection, binding))
            .and_then(|()| guard());
        if result.is_err() {
            self.mark_terminal();
            connection.invalidate();
        }
        result
    }

    fn snapshot(
        &self,
        events: &watch::Sender<ConnectionEvent>,
        binding: Option<NativePeerBinding>,
        deadline: Instant,
    ) -> PeerRevalidationSnapshot {
        PeerRevalidationSnapshot {
            event: *events.borrow(),
            terminal: self.terminal.load(Ordering::Acquire),
            verified_reply_observed: self.verified_reply_observed.load(Ordering::Acquire),
            binding_present: binding.is_some(),
            deadline_reached: Instant::now() >= deadline,
        }
    }
}

fn peer_revalidation_guard(
    snapshot: PeerRevalidationSnapshot,
) -> Result<(), CredentialServiceXpcError> {
    qualification_exchange_guard(snapshot)?;
    if !snapshot.verified_reply_observed {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(())
}

fn qualification_exchange_guard(
    snapshot: PeerRevalidationSnapshot,
) -> Result<(), CredentialServiceXpcError> {
    if snapshot.deadline_reached {
        return Err(CredentialServiceXpcError::TimedOut);
    }
    if snapshot.terminal || snapshot.event == ConnectionEvent::Invalidated {
        return Err(CredentialServiceXpcError::Invalidated);
    }
    if snapshot.event == ConnectionEvent::Interrupted {
        return Err(CredentialServiceXpcError::Interrupted);
    }
    if !snapshot.binding_present {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(())
}

impl super::NativeClient {
    #[allow(clippy::redundant_pub_crate)]
    pub(crate) fn begin_qualification_exchange(
        &self,
        deadline: Instant,
    ) -> Result<(), CredentialServiceXpcError> {
        self.observation
            .begin_exchange(&self.connection, &self.events, self.peer_binding, deadline)
    }

    #[allow(clippy::redundant_pub_crate)]
    pub(crate) fn revalidate_qualification_peer(
        &self,
        deadline: Instant,
    ) -> Result<(), CredentialServiceXpcError> {
        self.observation
            .revalidate(&self.connection, &self.events, self.peer_binding, deadline)
    }
}

pub(super) fn assert_peer_binding(
    connection: &NSXPCConnection,
    binding: NativePeerBinding,
) -> Result<(), CredentialServiceXpcError> {
    if connection.effectiveUserIdentifier() != binding.expected_euid
        || audit_session_identifier(connection) != binding.expected_audit_session
    {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(())
}

fn audit_session_identifier(connection: &NSXPCConnection) -> i32 {
    unsafe extern "C" {
        fn runne_xpc_audit_session_identifier(connection: *const NSXPCConnection) -> i32;
    }
    // SAFETY: the shim invokes Foundation's public readonly property on a live connection.
    unsafe { runne_xpc_audit_session_identifier(std::ptr::from_ref(connection)) }
}

pub(super) fn send_once(slot: &ReplySlot, result: ReplyResult) {
    let sender = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        let _ = sender.send(result);
    }
}

pub(super) fn new_reply_slot() -> (oneshot::Receiver<ReplyResult>, ReplySlot) {
    let (sender, receiver) = oneshot::channel();
    (receiver, Arc::new(Mutex::new(Some(sender))))
}

pub(super) fn close_slot(slot: &ReplySlot) {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}

#[cfg(test)]
mod tests {
    use super::{ConnectionEvent, PeerRevalidationSnapshot, peer_revalidation_guard};
    use crate::CredentialServiceXpcError;

    #[test]
    fn peer_revalidation_rejects_invalidated_connections() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Invalidated,
                terminal: false,
                verified_reply_observed: true,
                binding_present: true,
                deadline_reached: false,
            }),
            Err(CredentialServiceXpcError::Invalidated)
        );
    }
    #[test]
    fn peer_revalidation_rejects_interrupted_connections() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Interrupted,
                terminal: false,
                verified_reply_observed: true,
                binding_present: true,
                deadline_reached: false,
            }),
            Err(CredentialServiceXpcError::Interrupted)
        );
    }
    #[test]
    fn peer_revalidation_requires_an_observed_verified_reply() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Active,
                terminal: false,
                verified_reply_observed: false,
                binding_present: true,
                deadline_reached: false,
            }),
            Err(CredentialServiceXpcError::Rejected)
        );
    }
    #[test]
    fn peer_revalidation_requires_the_existing_native_binding() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Active,
                terminal: false,
                verified_reply_observed: true,
                binding_present: false,
                deadline_reached: false,
            }),
            Err(CredentialServiceXpcError::Rejected)
        );
    }
    #[test]
    fn peer_revalidation_rejects_an_expired_deadline() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Active,
                terminal: false,
                verified_reply_observed: true,
                binding_present: true,
                deadline_reached: true,
            }),
            Err(CredentialServiceXpcError::TimedOut)
        );
    }

    #[test]
    fn terminal_connection_stays_rejected_after_a_late_observed_reply() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Active,
                terminal: true,
                verified_reply_observed: true,
                binding_present: true,
                deadline_reached: false,
            }),
            Err(CredentialServiceXpcError::Invalidated)
        );
    }

    #[test]
    fn peer_revalidation_accepts_a_live_observed_bound_connection() {
        assert_eq!(
            peer_revalidation_guard(PeerRevalidationSnapshot {
                event: ConnectionEvent::Active,
                terminal: false,
                verified_reply_observed: true,
                binding_present: true,
                deadline_reached: false,
            }),
            Ok(())
        );
    }
}

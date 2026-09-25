use std::sync::{Arc, Mutex, Weak};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

use crate::CredentialServiceXpcError;
use crate::frame::{NativeReplyFrame, NativeRequestFrame};

pub type ReplyResult = Result<NativeReplyFrame, CredentialServiceXpcError>;

pub trait ConnectionInvalidator: Send + Sync {
    fn invalidate(&self);
}

#[derive(Clone, Copy)]
pub enum UnknownTerminal {
    Timeout,
    Cancelled,
    Interrupted,
    Invalidated,
    DispatchError,
    MalformedReply,
    ReceiverClosed,
    OwnerDropped,
}

struct TerminalState {
    request: Option<NativeRequestFrame>,
    sender: Option<oneshot::Sender<ReplyResult>>,
    closed: bool,
    reply_accepted: bool,
    invalidation_requested: bool,
    #[cfg(test)]
    terminal_witness: Option<Arc<AtomicUsize>>,
}

struct SharedCallState {
    terminal: Mutex<TerminalState>,
    invalidator: Weak<dyn ConnectionInvalidator>,
}

impl SharedCallState {
    fn finish(&self, delivery: Option<ReplyResult>, invalidate: bool) {
        let resources = {
            let mut terminal = self
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if terminal.closed {
                None
            } else {
                terminal.closed = true;
                #[cfg(test)]
                let witness = terminal.terminal_witness.take();
                #[cfg(not(test))]
                let witness: Option<()> = None;
                Some((terminal.request.take(), terminal.sender.take(), witness))
            }
        };
        let Some((request, sender, witness)) = resources else {
            if invalidate {
                self.invalidate_once();
            }
            return;
        };

        drop(request);
        #[cfg(test)]
        if let Some(witness) = witness {
            witness.fetch_add(1, Ordering::AcqRel);
        }
        #[cfg(not(test))]
        let _ = witness;

        let receiver_closed = match (sender, delivery) {
            (Some(sender), Some(result)) => sender.send(result).is_err(),
            (Some(sender), None) => {
                drop(sender);
                false
            }
            (None, result) => {
                drop(result);
                true
            }
        };
        if invalidate || receiver_closed {
            self.invalidate_once();
        }
    }

    fn accept_reply(&self) {
        let mut terminal = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(terminal.closed);
        terminal.reply_accepted = true;
    }

    fn reply_accepted(&self) -> bool {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reply_accepted
    }

    fn invalidate_once(&self) {
        let should_invalidate = {
            let mut terminal = self
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let first = !terminal.invalidation_requested;
            terminal.invalidation_requested = true;
            first
        };
        if should_invalidate && let Some(invalidator) = self.invalidator.upgrade() {
            // This runs outside the terminal mutex because NSXPC invalidation may
            // synchronously re-enter a connection event handler.
            invalidator.invalidate();
        }
    }
}

pub struct NativeCallState {
    shared: Arc<SharedCallState>,
}

impl NativeCallState {
    pub(crate) fn new(
        request: NativeRequestFrame,
        sender: oneshot::Sender<ReplyResult>,
        invalidator: &Arc<dyn ConnectionInvalidator>,
    ) -> Self {
        Self::build(request, sender, invalidator, None)
    }

    #[cfg(test)]
    pub(crate) fn new_observed(
        request: NativeRequestFrame,
        sender: oneshot::Sender<ReplyResult>,
        invalidator: &Arc<dyn ConnectionInvalidator>,
        terminal_witness: Arc<AtomicUsize>,
    ) -> Self {
        Self::build(request, sender, invalidator, Some(terminal_witness))
    }

    fn build(
        request: NativeRequestFrame,
        sender: oneshot::Sender<ReplyResult>,
        invalidator: &Arc<dyn ConnectionInvalidator>,
        #[cfg(test)] terminal_witness: Option<Arc<AtomicUsize>>,
        #[cfg(not(test))] _terminal_witness: Option<()>,
    ) -> Self {
        Self {
            shared: Arc::new(SharedCallState {
                terminal: Mutex::new(TerminalState {
                    request: Some(request),
                    sender: Some(sender),
                    closed: false,
                    reply_accepted: false,
                    invalidation_requested: false,
                    #[cfg(test)]
                    terminal_witness,
                }),
                invalidator: Arc::downgrade(invalidator),
            }),
        }
    }

    pub(crate) fn reply_handle(&self) -> NativeReplyHandle {
        NativeReplyHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    pub(crate) fn close_unknown(&self, terminal: UnknownTerminal) {
        let _ = terminal;
        self.shared.finish(None, true);
    }

    pub(crate) fn accept_reply(&self) {
        self.shared.accept_reply();
    }
}

impl Drop for NativeCallState {
    fn drop(&mut self) {
        if !self.shared.reply_accepted() {
            self.close_unknown(UnknownTerminal::OwnerDropped);
        }
    }
}

#[derive(Clone)]
pub struct NativeReplyHandle {
    shared: Arc<SharedCallState>,
}

impl NativeReplyHandle {
    pub(crate) fn deliver(&self, result: ReplyResult) {
        let invalidate = result.is_err();
        self.shared.finish(Some(result), invalidate);
    }

    pub(crate) fn deliver_unknown(&self, terminal: UnknownTerminal) {
        let _ = terminal;
        self.shared
            .finish(Some(Err(CredentialServiceXpcError::OutcomeUnknown)), true);
    }

    #[cfg(test)]
    pub(crate) fn simulate_sender_loss(&self) {
        self.shared.finish(None, false);
    }
}

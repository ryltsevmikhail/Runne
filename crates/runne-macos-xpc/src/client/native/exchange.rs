use std::sync::Arc;
use std::time::Instant;

use runne_platform_ports::credential_service::CredentialServiceCallContext;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

use super::call_state::{
    ConnectionInvalidator, NativeCallState, NativeReplyHandle, ReplyResult, UnknownTerminal,
};
use crate::CredentialServiceXpcError;
#[cfg(test)]
use crate::frame::FrameDropWitness;
use crate::frame::{NativeReplyFrame, NativeRequestFrame};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionEvent {
    Active,
    Interrupted,
    Invalidated,
}

pub trait ExchangeConnection: ConnectionInvalidator + Send + Sync + 'static {
    type PreparedRequest;

    fn subscribe(&self) -> watch::Receiver<ConnectionEvent>;
    fn prepare(&self, request: &NativeRequestFrame) -> Self::PreparedRequest;
    fn dispatch(
        &self,
        request: Self::PreparedRequest,
        callbacks: NativeCallbacks,
    ) -> Result<(), ()>;
}

#[derive(Clone)]
pub struct NativeCallbacks {
    reply: NativeReplyHandle,
}

impl NativeCallbacks {
    const fn new(reply: NativeReplyHandle) -> Self {
        Self { reply }
    }

    pub fn valid_reply(&self, reply: NativeReplyFrame) {
        self.reply.deliver(Ok(reply));
    }

    pub fn native_reply(&self, result: Result<NativeReplyFrame, CredentialServiceXpcError>) {
        match result {
            Ok(reply) => self.valid_reply(reply),
            Err(_) => self.reply.deliver_unknown(UnknownTerminal::MalformedReply),
        }
    }

    pub fn proxy_error(&self) {
        self.reply.deliver_unknown(UnknownTerminal::DispatchError);
    }

    #[cfg(test)]
    pub fn simulate_sender_loss(&self) {
        self.reply.simulate_sender_loss();
    }
}

struct Witnesses {
    #[cfg(test)]
    observed: Option<TestWitnesses>,
}

impl Witnesses {
    const fn none() -> Self {
        Self {
            #[cfg(test)]
            observed: None,
        }
    }
}

#[cfg(test)]
pub struct TestWitnesses {
    request_drop: FrameDropWitness,
    terminal: Arc<AtomicUsize>,
}

#[cfg(test)]
impl TestWitnesses {
    pub fn new(request_drop: FrameDropWitness, terminal: Arc<AtomicUsize>) -> Self {
        Self {
            request_drop,
            terminal,
        }
    }
}

pub async fn exchange<C>(
    connection: Arc<C>,
    bytes: Zeroizing<Vec<u8>>,
    context: CredentialServiceCallContext,
) -> ReplyResult
where
    C: ExchangeConnection,
{
    exchange_inner(connection, bytes, context, Witnesses::none()).await
}

#[cfg(test)]
pub async fn exchange_observed<C>(
    connection: Arc<C>,
    bytes: Zeroizing<Vec<u8>>,
    context: CredentialServiceCallContext,
    witnesses: TestWitnesses,
) -> ReplyResult
where
    C: ExchangeConnection,
{
    exchange_inner(
        connection,
        bytes,
        context,
        Witnesses {
            observed: Some(witnesses),
        },
    )
    .await
}

async fn exchange_inner<C>(
    connection: Arc<C>,
    bytes: Zeroizing<Vec<u8>>,
    context: CredentialServiceCallContext,
    witnesses: Witnesses,
) -> ReplyResult
where
    C: ExchangeConnection,
{
    if context.cancellation().is_cancelled() {
        return Err(CredentialServiceXpcError::Cancelled);
    }
    if Instant::now() >= context.deadline() {
        return Err(CredentialServiceXpcError::TimedOut);
    }
    let mut events = connection.subscribe();
    let connection_event = *events.borrow();
    match connection_event {
        ConnectionEvent::Active => {}
        ConnectionEvent::Interrupted => return Err(CredentialServiceXpcError::Interrupted),
        ConnectionEvent::Invalidated => return Err(CredentialServiceXpcError::Invalidated),
    }
    let request = make_request(bytes, &witnesses)?;
    if context.cancellation().is_cancelled() {
        return Err(CredentialServiceXpcError::Cancelled);
    }
    if Instant::now() >= context.deadline() {
        return Err(CredentialServiceXpcError::TimedOut);
    }
    let prepared = connection.prepare(&request);
    let (sender, mut receiver) = oneshot::channel();
    let invalidator: Arc<dyn ConnectionInvalidator> = connection.clone();
    let call = make_call(request, sender, &invalidator, &witnesses);
    if connection
        .dispatch(prepared, NativeCallbacks::new(call.reply_handle()))
        .is_err()
    {
        call.close_unknown(UnknownTerminal::DispatchError);
        return Err(CredentialServiceXpcError::OutcomeUnknown);
    }

    let timeout = tokio::time::sleep_until(context.deadline().into());
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        () = &mut timeout => {
            call.close_unknown(UnknownTerminal::Timeout);
            Err(CredentialServiceXpcError::OutcomeUnknown)
        }
        () = context.cancellation().cancelled() => {
            call.close_unknown(UnknownTerminal::Cancelled);
            Err(CredentialServiceXpcError::OutcomeUnknown)
        }
        changed = events.changed() => {
            let terminal = match changed.map(|()| *events.borrow()) {
                Ok(ConnectionEvent::Interrupted) => UnknownTerminal::Interrupted,
                Ok(ConnectionEvent::Invalidated | ConnectionEvent::Active) | Err(_) => {
                    UnknownTerminal::Invalidated
                }
            };
            call.close_unknown(terminal);
            Err(CredentialServiceXpcError::OutcomeUnknown)
        }
        result = &mut receiver => {
            let result = result.unwrap_or_else(|_| {
                call.close_unknown(UnknownTerminal::ReceiverClosed);
                Err(CredentialServiceXpcError::OutcomeUnknown)
            });
            if result.is_ok() {
                call.accept_reply();
            }
            result
        },
    }
}

fn make_request(
    bytes: Zeroizing<Vec<u8>>,
    witnesses: &Witnesses,
) -> Result<NativeRequestFrame, CredentialServiceXpcError> {
    #[cfg(test)]
    if let Some(observed) = &witnesses.observed {
        return NativeRequestFrame::new_observed(bytes, observed.request_drop.clone());
    }
    #[cfg(not(test))]
    let _ = witnesses;
    NativeRequestFrame::new(bytes)
}

fn make_call(
    request: NativeRequestFrame,
    sender: oneshot::Sender<ReplyResult>,
    invalidator: &Arc<dyn ConnectionInvalidator>,
    witnesses: &Witnesses,
) -> NativeCallState {
    #[cfg(test)]
    if let Some(observed) = &witnesses.observed {
        return NativeCallState::new_observed(
            request,
            sender,
            invalidator,
            Arc::clone(&observed.terminal),
        );
    }
    #[cfg(not(test))]
    let _ = witnesses;
    NativeCallState::new(request, sender, invalidator)
}

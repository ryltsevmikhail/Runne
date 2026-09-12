use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

use runne_api::{
    BootstrapAck, BootstrapControlReply, BootstrapControlRequest, RootConsumeRequest, RootPrepared,
};
use runne_macos_xpc::{
    QualificationRunnerReply, QualificationRunnerRequest, QualificationRunnerXpcClient,
    QualificationRunnerXpcError,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc::{Sender, channel};
use zeroize::Zeroizing;

use crate::coordinator::{RuntimeTicket, same_binding};

#[derive(Clone, Copy, Debug)]
pub struct BridgeError;

pub struct RootBridge {
    sender: Sender<Command>,
}

enum Command {
    Prepare {
        deadline: Instant,
        reply: SyncSender<Result<RootPrepared, BridgeError>>,
    },
    Complete {
        request: runne_api::RuntimeBootstrapRequest,
        ticket: Box<RuntimeTicket>,
        reply: SyncSender<Result<BootstrapAck, BridgeError>>,
    },
}

impl RootBridge {
    pub(crate) fn start(client: QualificationRunnerXpcClient) -> Option<Self> {
        let (sender, mut receiver) = channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("runne-qualification-root-bridge".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build();
                let Ok(runtime) = runtime else {
                    let _ = ready_sender.send(false);
                    return;
                };
                let _ = ready_sender.send(true);
                runtime.block_on(async move {
                    while let Some(command) = receiver.recv().await {
                        let terminal = match command {
                            Command::Prepare { deadline, reply } => {
                                let result = prepare(&client, deadline).await;
                                let terminal = result.is_err();
                                let _ = reply.send(result);
                                terminal
                            }
                            Command::Complete {
                                request,
                                ticket,
                                reply,
                            } => {
                                let result = complete(&client, request, *ticket).await;
                                let _ = reply.send(result);
                                true
                            }
                        };
                        if terminal {
                            break;
                        }
                    }
                });
            })
            .ok()?;
        ready_receiver
            .recv_timeout(Duration::from_secs(1))
            .ok()?
            .then_some(Self { sender })
    }

    pub(crate) fn prepare(&self, deadline: Instant) -> Result<RootPrepared, BridgeError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Command::Prepare {
                deadline,
                reply: sender,
            })
            .map_err(|_| BridgeError)?;
        receive(&receiver, deadline)
    }

    pub(crate) fn complete(
        &self,
        request: runne_api::RuntimeBootstrapRequest,
        ticket: RuntimeTicket,
    ) -> Result<BootstrapAck, BridgeError> {
        let deadline = ticket.deadline();
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Command::Complete {
                request,
                ticket: Box::new(ticket),
                reply: sender,
            })
            .map_err(|_| BridgeError)?;
        receive(&receiver, deadline)
    }
}

fn receive<T>(
    receiver: &mpsc::Receiver<Result<T, BridgeError>>,
    deadline: Instant,
) -> Result<T, BridgeError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or(BridgeError)?;
    receiver.recv_timeout(timeout).map_err(|_| BridgeError)?
}

async fn prepare(
    client: &QualificationRunnerXpcClient,
    deadline: Instant,
) -> Result<RootPrepared, BridgeError> {
    match exchange(
        client,
        BootstrapControlRequest::RootPrepare(runne_api::RootPrepareRequest::new()),
        deadline,
    )
    .await?
    {
        BootstrapControlReply::RootPrepared(value) => Ok(value),
        _ => Err(BridgeError),
    }
}

async fn complete(
    client: &QualificationRunnerXpcClient,
    request: runne_api::RuntimeBootstrapRequest,
    ticket: RuntimeTicket,
) -> Result<BootstrapAck, BridgeError> {
    if !ticket.matches(&request) {
        return Err(BridgeError);
    }
    let offer_id = request.offer_id();
    let challenge = request.daemon_challenge();
    let issued = match exchange(
        client,
        BootstrapControlRequest::RootArm(request),
        ticket.deadline(),
    )
    .await?
    {
        BootstrapControlReply::RootIssuedProof(value)
            if value.offer_id() == offer_id && value.daemon_challenge() == challenge =>
        {
            value
        }
        _ => return Err(BridgeError),
    };
    let plan = consume_plan(issued, &ticket, challenge)?;
    let BootstrapControlReply::BootstrapAck(ack) = exchange(
        client,
        BootstrapControlRequest::RootConsume(plan.request),
        ticket.deadline(),
    )
    .await?
    else {
        return Err(BridgeError);
    };
    ack_matches(&ack, &ticket, challenge, plan.digest)
        .then_some(ack)
        .ok_or(BridgeError)
}

struct ConsumePlan {
    request: RootConsumeRequest,
    digest: [u8; 32],
}

fn consume_plan(
    issued: runne_api::RootIssuedProof,
    ticket: &RuntimeTicket,
    challenge: [u8; 32],
) -> Result<ConsumePlan, BridgeError> {
    if issued.offer_id() != ticket.offer_id() || issued.daemon_challenge() != challenge {
        return Err(BridgeError);
    }
    let proof = issued.into_signed_proof();
    let digest: [u8; 32] = Sha256::digest(&proof).into();
    let request =
        RootConsumeRequest::new(ticket.offer_id(), challenge, proof).map_err(|_| BridgeError)?;
    Ok(ConsumePlan { request, digest })
}

fn ack_matches(
    ack: &BootstrapAck,
    ticket: &RuntimeTicket,
    challenge: [u8; 32],
    digest: [u8; 32],
) -> bool {
    ack.offer_id() == ticket.offer_id()
        && ack.daemon_challenge() == challenge
        && ack.proof_sha256() == digest
        && ack.run_not_after() == ticket.run_not_after()
        && same_binding(ack.binding(), ticket.binding())
}

async fn exchange(
    client: &QualificationRunnerXpcClient,
    request: BootstrapControlRequest,
    deadline: Instant,
) -> Result<BootstrapControlReply, BridgeError> {
    let bytes = request.encode().map_err(|_| BridgeError)?;
    let request = QualificationRunnerRequest::from_zeroizing(Zeroizing::new(bytes))
        .map_err(|_| BridgeError)?;
    let reply = client
        .exchange(request, deadline)
        .await
        .map_err(map_error)?;
    decode(reply)
}

fn decode(reply: QualificationRunnerReply) -> Result<BootstrapControlReply, BridgeError> {
    BootstrapControlReply::decode(&reply.into_zeroizing()).map_err(|_| BridgeError)
}

const fn map_error(_: QualificationRunnerXpcError) -> BridgeError {
    BridgeError
}

#[cfg(test)]
#[path = "root_bridge/tests.rs"]
mod tests;

use std::sync::Arc;

use runne_api::{BootstrapControlReply, BootstrapControlRequest};
use runne_macos_xpc::{
    QualificationRunnerEndpoint, QualificationRunnerReply, QualificationRunnerRequest,
    QualificationRunnerSession, QualificationRunnerSessionContext,
    QualificationRunnerSessionFactory, QualificationRunnerSessionLease,
    QualificationRunnerSessionReceipt, QualificationRunnerXpcError,
};
use zeroize::Zeroizing;

use super::AdmissionSlot;
use crate::coordinator::{RunCoordinator, RuntimeTicket};
use crate::root_bridge::RootBridge;

pub(super) struct DesktopFactory {
    coordinator: Arc<RunCoordinator>,
    admission: Arc<AdmissionSlot>,
}

impl DesktopFactory {
    pub(super) const fn new(
        coordinator: Arc<RunCoordinator>,
        admission: Arc<AdmissionSlot>,
    ) -> Self {
        Self {
            coordinator,
            admission,
        }
    }
}

impl QualificationRunnerSessionFactory for DesktopFactory {
    fn create_session(
        &self,
        context: QualificationRunnerSessionContext,
    ) -> Result<QualificationRunnerSessionLease, QualificationRunnerXpcError> {
        if context.endpoint() != QualificationRunnerEndpoint::DesktopBootstrap {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        self.coordinator
            .claim_desktop()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let session = DesktopSession {
            coordinator: Arc::clone(&self.coordinator),
            admission: Arc::clone(&self.admission),
            complete: false,
            _receipt: context.into_receipt(),
        };
        QualificationRunnerSessionLease::new(Box::new(session), self.coordinator.deadline())
            .inspect_err(|_| self.coordinator.fail())
    }
}

pub(super) struct RuntimeFactory {
    coordinator: Arc<RunCoordinator>,
    root_bridge: Arc<RootBridge>,
    admission: Arc<AdmissionSlot>,
}

impl RuntimeFactory {
    pub(super) const fn new(
        coordinator: Arc<RunCoordinator>,
        root_bridge: Arc<RootBridge>,
        admission: Arc<AdmissionSlot>,
    ) -> Self {
        Self {
            coordinator,
            root_bridge,
            admission,
        }
    }
}

impl QualificationRunnerSessionFactory for RuntimeFactory {
    fn create_session(
        &self,
        context: QualificationRunnerSessionContext,
    ) -> Result<QualificationRunnerSessionLease, QualificationRunnerXpcError> {
        if context.endpoint() != QualificationRunnerEndpoint::RuntimeBootstrap {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        let ticket = self
            .coordinator
            .claim_runtime()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let session = RuntimeSession {
            coordinator: Arc::clone(&self.coordinator),
            root_bridge: Arc::clone(&self.root_bridge),
            admission: Arc::clone(&self.admission),
            ticket,
            complete: false,
            _receipt: context.into_receipt(),
        };
        QualificationRunnerSessionLease::new(Box::new(session), self.coordinator.deadline())
            .inspect_err(|_| self.coordinator.fail())
    }
}

struct DesktopSession {
    coordinator: Arc<RunCoordinator>,
    admission: Arc<AdmissionSlot>,
    complete: bool,
    _receipt: QualificationRunnerSessionReceipt,
}

impl QualificationRunnerSession for DesktopSession {
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        if self.complete {
            self.coordinator.fail();
            return Err(QualificationRunnerXpcError::Rejected);
        }
        let request = decode(request)?;
        let BootstrapControlRequest::DesktopOffer(request) = request else {
            self.coordinator.fail();
            return Err(QualificationRunnerXpcError::Rejected);
        };
        let offer = self
            .coordinator
            .desktop_offer(&request)
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        self.admission
            .refresh()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let reply = encode(&BootstrapControlReply::DesktopOffer(offer))?;
        self.admission
            .refresh()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        self.coordinator
            .finish_desktop()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        self.complete = true;
        Ok(reply)
    }
}

impl Drop for DesktopSession {
    fn drop(&mut self) {
        if !self.complete {
            self.coordinator.fail();
        }
    }
}

struct RuntimeSession {
    coordinator: Arc<RunCoordinator>,
    root_bridge: Arc<RootBridge>,
    admission: Arc<AdmissionSlot>,
    ticket: RuntimeTicket,
    complete: bool,
    _receipt: QualificationRunnerSessionReceipt,
}

impl QualificationRunnerSession for RuntimeSession {
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        if self.complete {
            self.coordinator.fail();
            return Err(QualificationRunnerXpcError::Rejected);
        }
        let request = decode(request)?;
        let BootstrapControlRequest::RuntimeBootstrap(request) = request else {
            self.coordinator.fail();
            return Err(QualificationRunnerXpcError::Rejected);
        };
        if !self.ticket.matches(&request) {
            self.coordinator.fail();
            return Err(QualificationRunnerXpcError::Rejected);
        }
        self.admission
            .refresh()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let worker_ticket = self
            .ticket
            .duplicate()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let ack = self
            .root_bridge
            .complete(request, worker_ticket)
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        self.admission
            .refresh()
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        self.coordinator
            .validate_runtime(&self.ticket, &ack)
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        let reply = encode(&BootstrapControlReply::BootstrapAck(ack))?;
        self.coordinator
            .finish_runtime()
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        self.complete = true;
        Ok(reply)
    }
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        if !self.complete {
            self.coordinator.fail();
        }
    }
}

fn decode(
    request: QualificationRunnerRequest,
) -> Result<BootstrapControlRequest, QualificationRunnerXpcError> {
    BootstrapControlRequest::decode(&request.into_zeroizing())
        .map_err(|_| QualificationRunnerXpcError::Rejected)
}

fn encode(
    reply: &BootstrapControlReply,
) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
    let bytes = reply
        .encode()
        .map_err(|_| QualificationRunnerXpcError::Rejected)?;
    QualificationRunnerReply::from_zeroizing(Zeroizing::new(bytes))
}

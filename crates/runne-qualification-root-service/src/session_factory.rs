use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runne_api::{BootstrapControlReply, BootstrapControlRequest};
use runne_macos_xpc::{
    QualificationRunnerEndpoint, QualificationRunnerReply, QualificationRunnerRequest,
    QualificationRunnerSession, QualificationRunnerSessionContext,
    QualificationRunnerSessionFactory, QualificationRunnerSessionLease,
    QualificationRunnerSessionReceipt, QualificationRunnerXpcError,
};
use zeroize::Zeroizing;

use crate::state::RootState;

pub struct Factory {
    pub state: Arc<Mutex<RootState>>,
    pub expected_euid: u32,
    pub expected_audit_session: i32,
    pub deadline: Instant,
}

impl QualificationRunnerSessionFactory for Factory {
    fn create_session(
        &self,
        context: QualificationRunnerSessionContext,
    ) -> Result<QualificationRunnerSessionLease, QualificationRunnerXpcError> {
        if context.endpoint() != QualificationRunnerEndpoint::RootConsume
            || context.peer().euid() != self.expected_euid
            || context.peer().audit_session() != self.expected_audit_session
        {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        self.state
            .lock()
            .map_err(|_| QualificationRunnerXpcError::Unavailable)?
            .revalidate()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_mins(15))
            .ok_or(QualificationRunnerXpcError::Unavailable)?
            .min(self.deadline);
        QualificationRunnerSessionLease::new(
            Box::new(Session {
                state: self.state.clone(),
                phase: Phase::Ready,
                _receipt: context.into_receipt(),
            }),
            deadline,
        )
    }
}

enum Phase {
    Ready,
    Prepared([u8; 32]),
    Issued([u8; 32]),
    Terminal,
}

struct Session {
    state: Arc<Mutex<RootState>>,
    phase: Phase,
    _receipt: QualificationRunnerSessionReceipt,
}

impl QualificationRunnerSession for Session {
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        let phase = std::mem::replace(&mut self.phase, Phase::Terminal);
        let request = BootstrapControlRequest::decode(&request.into_zeroizing())
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| QualificationRunnerXpcError::Unavailable)?;
        state
            .revalidate()
            .map_err(|_| QualificationRunnerXpcError::Rejected)?;
        let (reply, next) = match (phase, request) {
            (Phase::Ready, BootstrapControlRequest::RootPrepare(_)) => {
                let reply = state
                    .prepare()
                    .map_err(|_| QualificationRunnerXpcError::Rejected)?;
                let next = Phase::Prepared(reply.offer_id());
                (BootstrapControlReply::RootPrepared(reply), next)
            }
            (Phase::Prepared(offer_id), BootstrapControlRequest::RootArm(request))
                if request.offer_id() == offer_id =>
            {
                let reply = state
                    .arm(&request)
                    .map_err(|_| QualificationRunnerXpcError::Rejected)?;
                (
                    BootstrapControlReply::RootIssuedProof(reply),
                    Phase::Issued(offer_id),
                )
            }
            (Phase::Issued(offer_id), BootstrapControlRequest::RootConsume(request))
                if request.offer_id() == offer_id =>
            {
                let reply = state
                    .consume(request)
                    .map_err(|_| QualificationRunnerXpcError::Rejected)?;
                (BootstrapControlReply::BootstrapAck(reply), Phase::Terminal)
            }
            _ => return Err(QualificationRunnerXpcError::Rejected),
        };
        state
            .revalidate()
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        drop(state);
        let bytes = reply
            .encode()
            .map_err(|_| QualificationRunnerXpcError::OutcomeUnknown)?;
        self.phase = next;
        QualificationRunnerReply::from_zeroizing(Zeroizing::new(bytes))
    }
}

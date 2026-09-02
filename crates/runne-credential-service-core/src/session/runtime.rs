use runne_api::CredentialServiceRuntimeEnvelope;
use runne_provider::{
    CredentialMaterial, CredentialServiceDisposition, CredentialServiceEndpointRole,
    CredentialServiceIngressRequest, CredentialServiceProtocolCodec, CredentialServiceReply,
    CredentialServiceReplyFrame,
};

use crate::backend::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRuntimeReadEffect,
    CredentialRuntimeReadObservation, execute_read,
};

use super::{CredentialServiceCore, CredentialServiceIngressFailure};

impl CredentialServiceCore {
    /// Handles one owner-routed, MAC-authenticated runtime request and returns a `MAC`-protected reply.
    ///
    /// The routing hint selects only a candidate session; inner owner equality is checked after MAC.
    ///
    /// # Errors
    ///
    /// Returns `Invalidate` only when no authenticated canonical context exists.
    pub fn handle_runtime(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
        backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
    ) -> Result<CredentialServiceRuntimeEnvelope, CredentialServiceIngressFailure> {
        if listener_role != CredentialServiceEndpointRole::Runtime {
            return Err(CredentialServiceIngressFailure::Invalidate);
        }
        let (owner, request) = self.decode_runtime(bytes, now)?;
        let context = request.context();
        let reply = match request {
            CredentialServiceIngressRequest::RuntimeMutationArm(request) => self
                .arm_request(owner, request, now)
                .map_or_else(CredentialServiceReply::Rejected, |()| {
                    CredentialServiceReply::Armed
                }),
            CredentialServiceIngressRequest::MetadataReadback(request) => {
                self.metadata_request(owner, &request, now, backend)
            }
            CredentialServiceIngressRequest::PointOfUseRead(request) => {
                self.point_read_request(owner, &request, now, backend)
            }
            _ => return Err(CredentialServiceIngressFailure::Invalidate),
        };
        let frame = CredentialServiceProtocolCodec::encode_reply(context, reply)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let session = self
            .sessions
            .get(&owner)
            .ok_or(CredentialServiceIngressFailure::Invalidate)?;
        let mut envelope = None;
        frame.send(|payload| {
            envelope = Some(
                session
                    .authenticator
                    .authenticate_runtime_reply(owner, payload)
                    .map_err(|_| CredentialServiceIngressFailure::Invalidate)?,
            );
            Ok(())
        })?;
        envelope.ok_or(CredentialServiceIngressFailure::Invalidate)
    }

    /// Handles one canonical writer request and returns its exact context-bound reply.
    ///
    /// # Errors
    ///
    /// Returns `Invalidate` only for a wrong listener or malformed pre-context frame.
    pub fn handle_writer(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
        backend: impl FnOnce(CredentialMutationEffect<'_>) -> CredentialBackendResult<()>,
    ) -> Result<CredentialServiceReplyFrame, CredentialServiceIngressFailure> {
        if listener_role != CredentialServiceEndpointRole::Writer {
            return Err(CredentialServiceIngressFailure::Invalidate);
        }
        let request = CredentialServiceProtocolCodec::decode_writer_request(bytes)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let context = request.context();
        let CredentialServiceIngressRequest::WriterConsume(request) = request else {
            return Err(CredentialServiceIngressFailure::Invalidate);
        };
        let owner = request.installation_owner();
        self.require_live_session(owner, now)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let reply = match self.admissions.consume(owner, request, now, backend) {
            Err(disposition) => CredentialServiceReply::Rejected(disposition),
            Ok(result) => mutation_reply(&result),
        };
        CredentialServiceProtocolCodec::encode_reply(context, reply)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)
    }

    fn arm_request(
        &mut self,
        owner: [u8; 32],
        request: runne_provider::CredentialRuntimeMutationAdmission,
        now: u64,
    ) -> Result<(), CredentialServiceDisposition> {
        let sequence = request.sequence().get();
        self.validate_runtime_binding(
            owner,
            request.installation_owner(),
            request.epoch(),
            request.session(),
            request.runtime_generation(),
            request.release_binding().as_bytes(),
            sequence,
            request.deadline(),
            now,
        )?;
        self.admissions.arm(owner, request, now)?;
        self.advance_sequence(owner, sequence)
    }

    fn metadata_request(
        &mut self,
        owner: [u8; 32],
        request: &runne_provider::CredentialMetadataReadbackAdmission,
        now: u64,
        backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
    ) -> CredentialServiceReply {
        let binding = request.binding();
        if let Err(error) = self.validate_read(owner, binding, now) {
            return CredentialServiceReply::Rejected(error);
        }
        let version = binding.version().clone();
        if let Err(error) = self.advance_sequence(owner, binding.sequence().get()) {
            return CredentialServiceReply::Rejected(error);
        }
        match execute_read(backend, CredentialRuntimeReadEffect::Metadata(&version)) {
            Some(CredentialRuntimeReadObservation::Metadata(result)) => metadata_reply(&result),
            _ => CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable),
        }
    }

    fn point_read_request(
        &mut self,
        owner: [u8; 32],
        request: &runne_provider::CredentialPointOfUseReadAdmission,
        now: u64,
        backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
    ) -> CredentialServiceReply {
        let binding = request.binding();
        if let Err(error) = self.validate_read(owner, binding, now) {
            return CredentialServiceReply::Rejected(error);
        }
        let receipt = request.receipt().digest().as_bytes();
        let Some(session) = self.sessions.get_mut(&owner) else {
            return CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied);
        };
        session.read_receipts.retain(|_, expiry| *expiry > now);
        if session.read_receipts.contains_key(&receipt) {
            return CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied);
        }
        if session.read_receipts.len() == 64 {
            return CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable);
        }
        session
            .read_receipts
            .insert(receipt, binding.deadline().expires_at_unix_millis());
        session.last_sequence = binding.sequence().get();
        let version = binding.version().clone();
        match execute_read(backend, CredentialRuntimeReadEffect::PointOfUse(&version)) {
            Some(CredentialRuntimeReadObservation::PointOfUse(result)) => material_reply(result),
            _ => CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable),
        }
    }
}

const fn mutation_reply(result: &CredentialBackendResult<()>) -> CredentialServiceReply {
    match result {
        CredentialBackendResult::Observed(()) => CredentialServiceReply::Consumed,
        CredentialBackendResult::Absent | CredentialBackendResult::AccessDenied => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied)
        }
        CredentialBackendResult::Unsupported => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unsupported)
        }
        CredentialBackendResult::Unavailable => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
        }
        CredentialBackendResult::Uncertain => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Uncertain)
        }
    }
}

const fn metadata_reply(result: &CredentialBackendResult<()>) -> CredentialServiceReply {
    match result {
        CredentialBackendResult::Observed(()) => CredentialServiceReply::Metadata { present: true },
        CredentialBackendResult::Absent => CredentialServiceReply::Metadata { present: false },
        CredentialBackendResult::AccessDenied => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied)
        }
        CredentialBackendResult::Unsupported => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unsupported)
        }
        CredentialBackendResult::Unavailable | CredentialBackendResult::Uncertain => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
        }
    }
}

fn material_reply(result: CredentialBackendResult<CredentialMaterial>) -> CredentialServiceReply {
    match result {
        CredentialBackendResult::Observed(material) => CredentialServiceReply::Material(material),
        CredentialBackendResult::Absent | CredentialBackendResult::AccessDenied => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Denied)
        }
        CredentialBackendResult::Unsupported => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unsupported)
        }
        CredentialBackendResult::Unavailable | CredentialBackendResult::Uncertain => {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
        }
    }
}

use std::collections::BTreeMap;

use runne_api::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_provider::{
    CredentialBindingDigest, CredentialMaterial, CredentialOperationAction,
    CredentialServiceDisposition, CredentialServiceEndpointRole, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequest, CredentialVersionRef,
};

use super::super::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRegistrationOutcome,
    CredentialRuntimeReadEffect, CredentialRuntimeReadObservation, CredentialServiceCore,
    CredentialServiceIngressFailure,
};

mod frames;
pub(super) use frames::{
    arm_frame, arm_frame_for_owner, arm_frame_with_grant_for_owner, mutation_frames, read_frame,
    read_frame_at,
};

pub(super) const OWNER: [u8; 32] = [3; 32];
pub(super) const EPOCH: [u8; 16] = [2; 16];
pub(super) const SESSION: [u8; 16] = [1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 2];

pub(super) struct MemoryBackend {
    pub(super) items: BTreeMap<(String, u64), Vec<u8>>,
    pub(super) next: CredentialBackendResult<()>,
    pub(super) panic_after_write: bool,
}

impl MemoryBackend {
    pub(super) fn new() -> Self {
        Self {
            items: BTreeMap::new(),
            next: CredentialBackendResult::Observed(()),
            panic_after_write: false,
        }
    }

    pub(super) fn mutate(
        &mut self,
        effect: CredentialMutationEffect<'_>,
    ) -> CredentialBackendResult<()> {
        let command = effect.command().clone();
        let Some(version) = command.target().version_ref() else {
            return CredentialBackendResult::Unsupported;
        };
        let key = key(version);
        if command.action() == CredentialOperationAction::Pair {
            effect.into_material().consume(|bytes| {
                self.items.insert(key, bytes.to_vec());
            });
        } else if command.action() == CredentialOperationAction::Revoke {
            self.items.remove(&key);
        }
        assert!(
            !self.panic_after_write,
            "simulated native crash after effect"
        );
        std::mem::replace(&mut self.next, CredentialBackendResult::Observed(()))
    }

    pub(super) fn metadata(&self, version: &CredentialVersionRef) -> CredentialBackendResult<()> {
        if self.items.contains_key(&key(version)) {
            CredentialBackendResult::Observed(())
        } else {
            CredentialBackendResult::Absent
        }
    }

    pub(super) fn read(
        &self,
        version: &CredentialVersionRef,
    ) -> CredentialBackendResult<CredentialMaterial> {
        self.items
            .get(&key(version))
            .map_or(CredentialBackendResult::Absent, |value| {
                CredentialBackendResult::Observed(
                    CredentialMaterial::from_bytes(value.clone()).unwrap(),
                )
            })
    }
}

pub(super) fn binding(
    join: u64,
    runtime: u64,
    installed: u64,
    expires: u64,
) -> CredentialServiceRegistrationBinding {
    let join_byte = u8::try_from(join).unwrap();
    binding_for_owner(OWNER, [join_byte; 16], join, runtime, installed, expires)
}

pub(super) fn binding_for_owner(
    owner: [u8; 32],
    nonce: [u8; 16],
    join: u64,
    runtime: u64,
    installed: u64,
    expires: u64,
) -> CredentialServiceRegistrationBinding {
    let mut session = SESSION;
    session[15] = u8::try_from(join).unwrap();
    CredentialServiceRegistrationBinding::new(
        EPOCH, session, 11, runtime, 13, installed, owner, [4; 32], nonce, join, expires,
    )
    .unwrap()
}

pub(super) fn register(
    core: &mut CredentialServiceCore,
    key: u8,
    binding: CredentialServiceRegistrationBinding,
    role: CredentialServiceEndpointRole,
) -> Result<
    (
        CredentialRegistrationOutcome,
        CredentialServiceRegistrationAck,
    ),
    CredentialServiceDisposition,
> {
    issue_challenge(core, *binding.challenge_nonce());
    replay_register(core, key, binding, role)
}

pub(super) fn replay_register(
    core: &mut CredentialServiceCore,
    key: u8,
    binding: CredentialServiceRegistrationBinding,
    role: CredentialServiceEndpointRole,
) -> Result<
    (
        CredentialRegistrationOutcome,
        CredentialServiceRegistrationAck,
    ),
    CredentialServiceDisposition,
> {
    replay_register_at(core, key, binding, role, 10)
}

pub(super) fn replay_register_at(
    core: &mut CredentialServiceCore,
    key: u8,
    binding: CredentialServiceRegistrationBinding,
    role: CredentialServiceEndpointRole,
    now: u64,
) -> Result<
    (
        CredentialRegistrationOutcome,
        CredentialServiceRegistrationAck,
    ),
    CredentialServiceDisposition,
> {
    let mut bytes = Vec::new();
    auth(key)
        .registration_install(binding)
        .unwrap()
        .send(|frame| {
            bytes.extend_from_slice(frame);
            Ok::<(), ()>(())
        })
        .unwrap();
    core.accept_registration_install(role, &bytes, now)
}

pub(super) fn runtime_reply(
    core: &mut CredentialServiceCore,
    bytes: &[u8],
    key: u8,
    now: u64,
    backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
) -> Result<CredentialServiceReply, CredentialServiceIngressFailure> {
    runtime_reply_for_owner(core, bytes, OWNER, key, now, backend)
}

pub(super) fn runtime_reply_for_owner(
    core: &mut CredentialServiceCore,
    bytes: &[u8],
    owner: [u8; 32],
    key: u8,
    now: u64,
    backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
) -> Result<CredentialServiceReply, CredentialServiceIngressFailure> {
    let authenticator = auth(key);
    let mut context = None;
    authenticator
        .verify_runtime_request(owner, bytes)
        .map_err(|_| CredentialServiceIngressFailure::Invalidate)?
        .consume(|payload| {
            context = CredentialServiceProtocolCodec::decode_runtime_request(payload)
                .ok()
                .map(|request| request.context());
        });
    let context = context.ok_or(CredentialServiceIngressFailure::Invalidate)?;
    let envelope =
        core.handle_runtime(CredentialServiceEndpointRole::Runtime, bytes, now, backend)?;
    let mut outer = Vec::new();
    envelope
        .send(|frame| {
            outer.extend_from_slice(frame);
            Ok::<(), ()>(())
        })
        .map_err(|()| CredentialServiceIngressFailure::Invalidate)?;
    let mut decoded = None;
    authenticator
        .verify_runtime_reply(owner, &outer)
        .map_err(|_| CredentialServiceIngressFailure::Invalidate)?
        .consume(|payload| {
            decoded = CredentialServiceProtocolCodec::decode_runtime_reply(payload, context).ok();
        });
    decoded.ok_or(CredentialServiceIngressFailure::Invalidate)
}

pub(super) fn writer_reply(
    core: &mut CredentialServiceCore,
    bytes: &[u8],
    now: u64,
    backend: impl FnOnce(CredentialMutationEffect<'_>) -> CredentialBackendResult<()>,
) -> Result<CredentialServiceReply, CredentialServiceIngressFailure> {
    let context = CredentialServiceProtocolCodec::decode_writer_request(bytes)
        .map_err(|_| CredentialServiceIngressFailure::Invalidate)?
        .context();
    let reply = core.handle_writer(CredentialServiceEndpointRole::Writer, bytes, now, backend)?;
    let mut frame = Vec::new();
    reply
        .send(|bytes| {
            frame.extend_from_slice(bytes);
            Ok::<(), ()>(())
        })
        .map_err(|()| CredentialServiceIngressFailure::Invalidate)?;
    CredentialServiceProtocolCodec::decode_writer_reply(&frame, context)
        .map_err(|_| CredentialServiceIngressFailure::Invalidate)
}

pub(super) fn issue_challenge(core: &mut CredentialServiceCore, nonce: [u8; 16]) {
    issue_challenge_at(core, nonce, 10);
}

pub(super) fn issue_challenge_at(core: &mut CredentialServiceCore, nonce: [u8; 16], now: u64) {
    let request = CredentialServiceProtocolCodec::encode_request(
        CredentialServiceRequest::RegistrationChallenge,
    )
    .unwrap();
    let mut bytes = Vec::new();
    request
        .send(|frame| {
            bytes.extend_from_slice(frame);
            Ok::<(), ()>(())
        })
        .unwrap();
    core.challenge_with_test_nonce(CredentialServiceEndpointRole::Desktop, &bytes, now, nonce)
        .unwrap();
}

pub(super) fn auth(byte: u8) -> CredentialServiceSessionAuthenticator {
    CredentialServiceSessionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([byte; 32]).unwrap().derive_keys(),
    )
}

pub(super) fn digest(byte: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([byte; 32]).unwrap()
}

fn key(version: &CredentialVersionRef) -> (String, u64) {
    (version.provider().as_str().to_owned(), version.version())
}

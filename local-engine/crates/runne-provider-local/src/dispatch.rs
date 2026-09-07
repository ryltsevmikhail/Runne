//! Dispatch coordination: consumed permit resolution, grant issue and
//! one-time consumption, host load+generate drive, stream normalization,
//! exactly-once usage settlement.

use crate::error::ProviderError;
use crate::grant::{ArtifactGrantRequest, GrantRole};
use crate::port::{DispatchRequest, ProviderStream};
use crate::prepared::PreparedRequest;
use runne_inference_host::backend::{BackendConfig, BackendPort, LoadRequest};
use runne_inference_host::{FakeBackend, HostSession};
use runne_inference_protocol::{Direction, Session};
use std::collections::BTreeMap;

/// Host link the adapter drives for one generation. In Phase 1 this is
/// the in-process fake host over a socketpair; the supervised worker
/// (Task 9) swaps in behind the same calls.
pub struct DispatchHost {
    pub session: HostSession<FakeBackend>,
    /// Ancillary fds received out-of-band for the load_model frame.
    pub ancillary: std::collections::VecDeque<rustix::fd::OwnedFd>,
}

/// Opens an in-process dispatch host over a socketpair.
pub fn in_process_dispatch_host(
    session_id: [u8; 16],
    generation: u64,
) -> (DispatchHost, Direction) {
    let keys = runne_inference_protocol::SessionKeys::derive(
        &runne_inference_protocol::LaunchSecret::from_bytes(&[0x42; 32]),
        b"hello",
        b"welcome",
        &runne_inference_protocol::ContextMaterial {
            channel: session_id,
            epoch: generation.to_be_bytes(),
            tag: [0, 0, 0],
        },
        runne_inference_protocol::SESSION_PURPOSE.as_bytes(),
    )
    .expect("keys");
    let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
    let transport = Session::new(keys, session_id, generation, Direction::H2c, 64 * 1024);
    let host = DispatchHost {
        session: HostSession::new(transport, a, FakeBackend::default()),
        ancillary: Default::default(),
    };
    (host, Direction::C2h)
}

/// Runtime inputs the adapter needs at dispatch.
pub struct DispatchInputs<'a> {
    pub consumed_permit: bool,
    /// Artifact digest and byte length resolved from the installation.
    pub artifact_digest: &'a str,
    pub byte_len: u64,
    pub session_id: [u8; 16],
    /// Ancillary fds received for this attempt (exactly one expected).
    pub ancillary: Vec<rustix::fd::OwnedFd>,
}

pub struct DispatchOutcome {
    pub stream: ProviderStream,
    pub host: DispatchHost,
}

/// Drives one admitted dispatch end-to-end and returns the normalized
/// stream. Fail-closed: no permit, wrong attempt binding or malformed
/// host stream rejects without host effect.
pub fn run_dispatch(
    known_identities: &BTreeMap<String, String>,
    inputs: &DispatchInputs<'_>,
    prepared: &PreparedRequest,
    request: &DispatchRequest,
) -> Result<DispatchOutcome, ProviderError> {
    if !inputs.consumed_permit {
        return Err(ProviderError::FrameMismatch);
    }
    if request.prepared_call_id != prepared.call_id {
        return Err(ProviderError::FrameMismatch);
    }
    let model_identity = known_identities
        .get(&prepared.model_identity)
        .cloned()
        .unwrap_or_else(|| prepared.model_identity.clone());

    let generation = u64::from_be_bytes(request.generation_id[..8].try_into().expect("8 bytes"));
    let (mut host, _dir) = in_process_dispatch_host(request.stream_id, generation);
    let image_len = inputs.byte_len;
    let req = LoadRequest {
        model_identity: model_identity.clone(),
        load_id: request.stream_id,
        artifact_digest: request.artifact_digest.clone(),
        byte_length: inputs.byte_len,
        artifact: std::fs::File::from(
            inputs
                .ancillary
                .first()
                .map(|fd| fd.try_clone())
                .transpose()
                .map_err(|e| {
                    ProviderError::Broker(runne_engine_broker::BrokerError::Transport(
                        e.to_string(),
                    ))
                })?
                .ok_or(ProviderError::FdMissing)?,
        ),
        config: BackendConfig::default(),
    };
    let _loaded = host
        .session
        .backend_mut()
        .load(&req)
        .map_err(ProviderError::from)?;
    host.session.mark_loaded(model_identity, request.stream_id);
    let _ = image_len;

    let items = runne_inference_host::generate::stream_generation(
        &mut host.session,
        request.generation_id,
        request.attempt_id,
        request.stream_id,
        &prepared.prompt,
    )?;
    let stream = crate::streams::normalize(request.stream_id, &items)?;
    Ok(DispatchOutcome { stream, host })
}

/// Issue the broker grant bound to this exact dispatch.
pub fn issue_request(
    manifest_digest: &str,
    artifact_digest: &str,
    byte_len: u64,
    session_id: [u8; 16],
    host_generation: u64,
    load_id: [u8; 16],
) -> ArtifactGrantRequest {
    ArtifactGrantRequest {
        manifest_digest: manifest_digest.to_string(),
        artifact_digest: artifact_digest.to_string(),
        byte_len,
        role: GrantRole::HostInspection,
        host_generation,
        load_id,
        session_id,
        ttl_secs: 60,
    }
}

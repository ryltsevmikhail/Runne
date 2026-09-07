//! `load_model` handling: validates binding, receives the ancillary fd,
//! runs bounded backend load. Per the frozen catalog there is no
//! `load_model` ack frame — load success is observable via the next
//! `generation_request`; failures are `error` frames.

use crate::error::HostError;
use crate::session::HostSession;
use runne_inference_protocol::MessageV1;

/// Takes ownership of exactly one ancillary fd (the artifact descriptor).
/// Zero or extra fds are closed and rejected.
pub fn take_single_fd(
    fds: &mut Vec<rustix::fd::OwnedFd>,
) -> Result<std::os::fd::OwnedFd, HostError> {
    if fds.len() != 1 {
        fds.clear();
        return Err(if fds.is_empty() {
            HostError::FdMissing
        } else {
            HostError::FdDuplicate
        });
    }
    Ok(fds.remove(0))
}

/// Processes an authenticated `load_model` frame plus its ancillary fd.
/// Success produces no wire frame (the next `generation_request` proves
/// the load); failures produce sanitized `error` frames.
pub fn handle_load<B: crate::backend::BackendPort>(
    host: &mut HostSession<B>,
    model_identity: &str,
    load_id: [u8; 16],
    _declared_len: u64,
    fds: &mut Vec<rustix::fd::OwnedFd>,
) -> Result<Option<MessageV1>, HostError> {
    host.require_ready()?;
    let artifact = take_single_fd(fds)?;
    let req = crate::backend::LoadRequest {
        model_identity: model_identity.to_string(),
        load_id,
        artifact: std::fs::File::from(artifact),
        // Digest/length arrive with the LoadModel frame in the caller
        // scope; the fake-path contract leaves them unset here.
        artifact_digest: String::new(),
        byte_length: 0,
        config: crate::backend::BackendConfig::default(),
    };
    let loaded = host.backend.load(&req)?;
    host.model_identity = Some(loaded.model_identity);
    host.load_id = Some(loaded.load_id);
    host.state = crate::session::HostState::Loaded;
    Ok(None)
}

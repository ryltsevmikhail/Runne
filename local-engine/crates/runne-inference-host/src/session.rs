//! Host session: the Booting→Ready→Loaded→Generating→Draining→Stopped
//! state machine over an authenticated protocol session. One model and
//! one generation are active; every transition validates generation/
//! session/load/attempt identity.

use crate::backend::BackendPort;
use crate::error::HostError;
use runne_inference_protocol::{MessageV1, ProtocolError, Session};
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Booting,
    Ready,
    Loaded,
    Generating,
    Draining,
    Stopped,
    Failed,
}

pub struct HostSession<B: BackendPort> {
    pub(crate) transport: Session,
    pub(crate) stream: UnixStream,
    pub(crate) backend: B,
    pub(crate) state: HostState,
    pub(crate) generation: u64,
    pub(crate) session_id: [u8; 16],
    pub(crate) model_identity: Option<String>,
    pub(crate) load_id: Option<[u8; 16]>,
    pub(crate) active_generation: Option<[u8; 16]>,
    pub(crate) active_attempt: Option<[u8; 16]>,
    pub(crate) active_stream: Option<[u8; 16]>,
}

impl<B: BackendPort> HostSession<B> {
    pub fn new(transport: Session, stream: UnixStream, backend: B) -> Self {
        let session_id = transport.session_id();
        let generation = transport.generation();
        Self {
            transport,
            stream,
            backend,
            state: HostState::Ready,
            generation,
            session_id,
            model_identity: None,
            load_id: None,
            active_generation: None,
            active_attempt: None,
            active_stream: None,
        }
    }

    pub fn state(&self) -> HostState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Backend access for host-side handlers (same crate boundary as the
    /// state machine).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Receives one authenticated client frame (strict next sequence).
    pub fn recv_frame(&mut self) -> Result<MessageV1, HostError> {
        let mut len_buf = [0u8; 4];
        read_exact(&mut self.stream, &mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; 4 + len];
        frame[..4].copy_from_slice(&len_buf);
        read_exact(&mut self.stream, &mut frame[4..])?;
        Ok(self.transport.decode(&frame)?)
    }

    /// Sends one authenticated host frame (h2c).
    pub fn send_frame(&mut self, message: &MessageV1) -> Result<(), HostError> {
        let frame = self.transport.encode(message)?;
        write_all(&mut self.stream, &frame)?;
        Ok(())
    }

    /// Host-side load completion: records identity and flips Ready→Loaded.
    pub fn mark_loaded(&mut self, model_identity: String, load_id: [u8; 16]) {
        self.model_identity = Some(model_identity);
        self.load_id = Some(load_id);
        self.state = HostState::Loaded;
    }

    /// State gate: only `Ready` admits `load_model`.
    pub(crate) fn require_ready(&self) -> Result<(), HostError> {
        if self.state != HostState::Ready {
            return Err(HostError::InvalidState);
        }
        Ok(())
    }

    /// State gate: only `Loaded` admits `generation_request`.
    pub(crate) fn require_loaded(&self) -> Result<(), HostError> {
        if self.state != HostState::Loaded {
            return Err(if self.state == HostState::Ready {
                HostError::ModelNotLoaded
            } else {
                HostError::InvalidState
            });
        }
        Ok(())
    }
}

fn read_exact(stream: &mut UnixStream, buf: &mut [u8]) -> Result<(), HostError> {
    std::io::Read::read_exact(stream, buf)
        .map_err(|_| HostError::Protocol(ProtocolError::Truncated))
}

fn write_all(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), HostError> {
    std::io::Write::write_all(stream, bytes)
        .map_err(|_| HostError::Protocol(ProtocolError::Truncated))
}

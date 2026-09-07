//! `WorkerBackend`: host-side `BackendPort` client of the supervised
//! worker session. Every frame is bound to the exact worker/host
//! generations and backend profile; the artifact descriptor is handed
//! over via SCM_RIGHTS exactly once per load; native worker failures
//! map to bounded host errors and fence the backend (no silent retry,
//! no backend substitution). Crash of the worker (abrupt EOF without a
//! terminal frame) fences the backend with `IntegrityViolation`.

use crate::backend::{BackendPort, GenerationCtx, LoadRequest, LoadedModel};
use crate::error::HostError;
use runne_inference_protocol::{
    Session, WorkerBackendConfig, WorkerErrorCode, WorkerFrameV1, WorkerWire,
};
use std::os::fd::AsFd;

/// Binding every worker frame must carry exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerBinding {
    pub worker_generation: [u8; 16],
    pub host_generation: [u8; 16],
    pub backend_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Loaded,
    Fenced,
}

pub struct WorkerBackend<W: WorkerWire> {
    wire: W,
    session: Session<WorkerFrameV1>,
    binding: WorkerBinding,
    config: WorkerBackendConfig,
    state: State,
    loaded_load_id: Option<[u8; 16]>,
}

impl<W: WorkerWire> WorkerBackend<W> {
    pub fn new(wire: W, session: Session<WorkerFrameV1>, binding: WorkerBinding) -> Self {
        Self {
            wire,
            session,
            binding,
            config: WorkerBackendConfig::default(),
            state: State::Idle,
            loaded_load_id: None,
        }
    }

    fn fenced(&self) -> Result<(), HostError> {
        if self.state == State::Fenced {
            Err(HostError::IntegrityViolation)
        } else {
            Ok(())
        }
    }

    fn check_binding(&self, frame: &WorkerFrameV1) -> Result<(), HostError> {
        let (wg, hg, profile) = frame.triple();
        if wg == self.binding.worker_generation
            && hg == self.binding.host_generation
            && profile == self.binding.backend_profile
        {
            Ok(())
        } else {
            Err(HostError::GenerationMismatch)
        }
    }

    fn send(&mut self, frame: WorkerFrameV1) -> Result<(), HostError> {
        let bytes = self.session.encode(&frame)?;
        self.wire.send_frame(&bytes)?;
        Ok(())
    }

    /// Receives the next worker frame with binding validation; wire
    /// failure here means worker death → fence + IntegrityViolation.
    fn recv(&mut self) -> Result<WorkerFrameV1, HostError> {
        let bytes = self.wire.recv_frame().map_err(|_| {
            self.state = State::Fenced;
            HostError::IntegrityViolation
        })?;
        let frame = self.session.decode(&bytes)?;
        self.check_binding(&frame)?;
        Ok(frame)
    }

    fn map_native(&self, code: WorkerErrorCode, detail: String) -> HostError {
        match code {
            WorkerErrorCode::DigestMismatch => HostError::ShaMismatch,
            WorkerErrorCode::LengthMismatch | WorkerErrorCode::LoadFailed => {
                HostError::CorruptModel
            }
            WorkerErrorCode::ContextExceeded
            | WorkerErrorCode::Memory
            | WorkerErrorCode::Unsupported
            | WorkerErrorCode::Cancelled
            | WorkerErrorCode::Internal => HostError::Worker { code, detail },
        }
    }

    /// Maps a worker error frame. Per plan: OOM fences the backend
    /// (forced containment); load/digest/context failures are
    /// attempt-level and leave the backend usable for an explicit
    /// supervisor-driven decision.
    fn error_of(&mut self, frame: WorkerFrameV1) -> HostError {
        match frame {
            WorkerFrameV1::BackendError { code, detail, .. } => {
                if code == WorkerErrorCode::Memory {
                    self.state = State::Fenced;
                }
                self.map_native(code, detail)
            }
            _ => {
                self.state = State::Fenced;
                HostError::ProtocolMismatch
            }
        }
    }
}

impl<W: WorkerWire> BackendPort for WorkerBackend<W> {
    fn load(&mut self, req: &LoadRequest) -> Result<LoadedModel, HostError> {
        self.fenced()?;
        if self.state == State::Loaded {
            return Err(HostError::ModelAlreadyActive);
        }
        self.send(WorkerFrameV1::BackendLoad {
            worker_generation: self.binding.worker_generation,
            host_generation: self.binding.host_generation,
            backend_profile: self.binding.backend_profile.clone(),
            load: runne_inference_protocol::WorkerLoad {
                model_identity: req.model_identity.clone(),
                load_id: req.load_id,
                artifact_digest: req.artifact_digest.clone(),
                byte_length: req.byte_length,
                load_fence: req.load_id,
            },
            config: self.config.clone(),
        })?;
        // Exactly one read-only descriptor follows the load frame.
        self.wire
            .send_fd(req.artifact.as_fd())
            .map_err(|_| self.fence_with(HostError::FdMissing))?;
        match self.recv()? {
            WorkerFrameV1::BackendLoaded {
                load_id,
                model_identity,
                ..
            } => {
                if load_id != req.load_id || model_identity != req.model_identity {
                    self.state = State::Fenced;
                    return Err(HostError::ArtifactGrantInvalid);
                }
                self.state = State::Loaded;
                self.loaded_load_id = Some(load_id);
                Ok(LoadedModel {
                    model_identity,
                    load_id,
                })
            }
            other => Err(self.error_of(other)),
        }
    }

    fn generate(
        &mut self,
        ctx: &GenerationCtx,
    ) -> Result<Vec<runne_inference_protocol::MessageV1>, HostError> {
        self.fenced()?;
        if self.state != State::Loaded {
            return Err(HostError::ModelNotLoaded);
        }
        self.send(WorkerFrameV1::BackendInfer {
            worker_generation: self.binding.worker_generation,
            host_generation: self.binding.host_generation,
            backend_profile: self.binding.backend_profile.clone(),
            generation_id: ctx.generation_id,
            attempt_id: ctx.attempt_id,
            stream_id: ctx.stream_id,
            prompt: ctx.prompt.clone(),
        })?;
        let mut out = Vec::new();
        let mut expected_seq = 0u64;
        let mut finished = false;
        loop {
            match self.recv()? {
                WorkerFrameV1::BackendItem {
                    stream_id,
                    stream_sequence,
                    kind,
                    payload,
                    ..
                } => {
                    if stream_id != ctx.stream_id || stream_sequence != expected_seq {
                        self.state = State::Fenced;
                        return Err(HostError::MalformedStream);
                    }
                    expected_seq += 1;
                    finished |= kind == "finish";
                    out.push(runne_inference_protocol::MessageV1::StreamItem {
                        generation_id: ctx.generation_id,
                        attempt_id: ctx.attempt_id,
                        stream_id: ctx.stream_id,
                        stream_sequence,
                        kind,
                        payload,
                    });
                }
                WorkerFrameV1::BackendTerminal { reason, .. } => {
                    if !finished {
                        // A cancelled or error-terminal stream may end
                        // without a finish item; synthesize one so the
                        // host ledger always has a terminal item.
                        out.push(runne_inference_protocol::MessageV1::StreamItem {
                            generation_id: ctx.generation_id,
                            attempt_id: ctx.attempt_id,
                            stream_id: ctx.stream_id,
                            stream_sequence: expected_seq,
                            kind: "finish".into(),
                            payload: reason.into_bytes(),
                        });
                    }
                    break;
                }
                other => return Err(self.error_of(other)),
            }
        }
        Ok(out)
    }

    fn cancel(&mut self) {
        // Phase-1 synchronous engine: cancel lands between calls; the
        // idle-cancel terminal keeps the frame exchange balanced.
        if self.state != State::Loaded {
            return;
        }
        let _ = self.send(WorkerFrameV1::BackendCancel {
            worker_generation: self.binding.worker_generation,
            host_generation: self.binding.host_generation,
            backend_profile: self.binding.backend_profile.clone(),
            cancel_id: self.binding.worker_generation,
        });
        let _ = self.recv();
    }

    fn unload(&mut self) -> Result<(), HostError> {
        self.fenced()?;
        if self.state != State::Loaded {
            return Err(HostError::ModelNotLoaded);
        }
        self.send(WorkerFrameV1::BackendUnload {
            worker_generation: self.binding.worker_generation,
            host_generation: self.binding.host_generation,
            backend_profile: self.binding.backend_profile.clone(),
            load_id: self.loaded_load_id.expect("load id tracked while loaded"),
        })?;
        match self.recv()? {
            WorkerFrameV1::BackendHealth { .. } => {
                self.state = State::Idle;
                self.loaded_load_id = None;
                Ok(())
            }
            other => Err(self.error_of(other)),
        }
    }
}

impl<W: WorkerWire> WorkerBackend<W> {
    fn fence_with(&mut self, err: HostError) -> HostError {
        self.state = State::Fenced;
        err
    }
}

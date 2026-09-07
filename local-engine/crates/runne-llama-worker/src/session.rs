//! Worker session loop: decodes the authenticated `backend_*` catalog,
//! binds every frame to the exact worker/host generations + profile,
//! drives the engine and emits strict from-zero stream sequences.
//! Engine-catalog (runtime) frames fail decode and close the session.
//! Mapping notes (Phase 1): `backend_unload` and `backend_health` are
//! answered with `backend_health` (idle ack); cancel is answered with
//! `backend_terminal{cancelled}` while idle cancellation is
//! `backend_error{cancelled}`.

use crate::engine::{EngineBackend, EngineFailure, EngineItem, EngineOutcome};
use runne_inference_protocol::error::ProtocolError;
use runne_inference_protocol::{
    WorkerBackendConfig, WorkerErrorCode, WorkerFrameV1, WorkerLoad, WorkerWire,
};

pub use crate::session_runner::serve;
pub use crate::session_usage::parse_usage_payload;
use crate::session_usage::usage_payload;

/// Identity every worker frame must carry exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerIdentity {
    pub worker_generation: [u8; 16],
    pub host_generation: [u8; 16],
    pub backend_profile: String,
}

pub struct WorkerSessionLoop<'a, W: WorkerWire, E: EngineBackend> {
    wire: &'a mut W,
    identity: WorkerIdentity,
    engine: &'a mut E,
    loaded: Option<WorkerLoad>,
    config: WorkerBackendConfig,
}

impl<'a, W: WorkerWire, E: EngineBackend> WorkerSessionLoop<'a, W, E> {
    pub fn new(wire: &'a mut W, identity: WorkerIdentity, engine: &'a mut E) -> Self {
        Self {
            wire,
            identity,
            engine,
            loaded: None,
            config: WorkerBackendConfig::default(),
        }
    }

    /// Runs until the wire fails, a fatal violation closes the session
    /// or the peer goes away. Returns the protocol error for
    /// diagnostics; the caller (supervisor) owns process exit policy.
    pub fn run(
        &mut self,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        loop {
            let frame_bytes = self.wire.recv_frame()?;
            let frame = session.decode(&frame_bytes)?;
            self.dispatch(frame, session)?;
        }
    }

    fn check_identity(&self, frame: &WorkerFrameV1) -> Result<(), ProtocolError> {
        let (wg, hg, profile) = frame.triple();
        if wg == self.identity.worker_generation
            && hg == self.identity.host_generation
            && profile == self.identity.backend_profile
        {
            Ok(())
        } else {
            Err(ProtocolError::IdentityMismatch)
        }
    }

    /// Returns Ok(true) when the session must close (shutdown path).
    fn dispatch(
        &mut self,
        frame: WorkerFrameV1,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        self.check_identity(&frame)?;
        match frame {
            WorkerFrameV1::BackendLoad { load, config, .. } => {
                self.handle_load(load, config, session)?;
            }
            WorkerFrameV1::BackendInfer {
                generation_id,
                attempt_id,
                stream_id,
                prompt,
                ..
            } => {
                self.handle_infer(generation_id, attempt_id, stream_id, &prompt, session)?;
            }
            WorkerFrameV1::BackendCancel { .. } => {
                self.handle_cancel(session)?;
            }
            WorkerFrameV1::BackendUnload { .. } => {
                if let Err(failure) = self.engine.unload() {
                    return self.fail(failure, session);
                }
                self.loaded = None;
                self.send(session, self.health())?;
            }
            WorkerFrameV1::BackendHealth { .. } => {
                self.send(session, self.health())?;
            }
            // No other catalog entry is ever inbound on the worker
            // channel; unexpected frames close the session.
            WorkerFrameV1::BackendLoaded { .. }
            | WorkerFrameV1::BackendItem { .. }
            | WorkerFrameV1::BackendTerminal { .. }
            | WorkerFrameV1::BackendError { .. } => {
                return Err(ProtocolError::ProtocolMismatch);
            }
        }
        Ok(())
    }

    fn handle_load(
        &mut self,
        load: WorkerLoad,
        config: WorkerBackendConfig,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        let artifact = self.wire.recv_fd()?;
        match self.engine.load(&load, &config, artifact) {
            Ok(()) => {
                self.loaded = Some(load.clone());
                self.config = config;
                let (wg, hg, profile) = self.id();
                self.send(
                    session,
                    WorkerFrameV1::BackendLoaded {
                        worker_generation: wg,
                        host_generation: hg,
                        backend_profile: profile,
                        load_id: load.load_id,
                        model_identity: load.model_identity,
                    },
                )
            }
            Err(failure) => self.fail(failure, session),
        }
    }

    fn handle_infer(
        &mut self,
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
        prompt: &str,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        if self.loaded.is_none() {
            return self.fail(
                EngineFailure::Native(WorkerErrorCode::LoadFailed, "no model".into()),
                session,
            );
        }
        match self
            .engine
            .infer(generation_id, attempt_id, stream_id, prompt)
        {
            Ok((items, outcome)) => {
                let (wg, hg, profile) = self.id();
                let mut usage = (0u64, 0u64);
                for (seq, item) in items.into_iter().enumerate() {
                    let seq = seq as u64;
                    let frame = match item {
                        EngineItem::Text(text) => WorkerFrameV1::BackendItem {
                            worker_generation: wg,
                            host_generation: hg,
                            backend_profile: profile.clone(),
                            stream_id,
                            stream_sequence: seq,
                            kind: "text".into(),
                            payload: text.into_bytes(),
                        },
                        EngineItem::Usage {
                            prompt_tokens,
                            output_tokens,
                        } => {
                            usage = (prompt_tokens, output_tokens);
                            WorkerFrameV1::BackendItem {
                                worker_generation: wg,
                                host_generation: hg,
                                backend_profile: profile.clone(),
                                stream_id,
                                stream_sequence: seq,
                                kind: "usage".into(),
                                payload: usage_payload(prompt_tokens, output_tokens),
                            }
                        }
                        EngineItem::Finish => WorkerFrameV1::BackendItem {
                            worker_generation: wg,
                            host_generation: hg,
                            backend_profile: profile.clone(),
                            stream_id,
                            stream_sequence: seq,
                            kind: "finish".into(),
                            payload: Vec::new(),
                        },
                    };
                    self.send(session, frame)?;
                }
                let reason = match outcome {
                    EngineOutcome::Stopped => "stop",
                    EngineOutcome::Cancelled => "cancelled",
                };
                let (wg, hg, profile) = self.id();
                self.send(
                    session,
                    WorkerFrameV1::BackendTerminal {
                        worker_generation: wg,
                        host_generation: hg,
                        backend_profile: profile,
                        stream_id,
                        reason: reason.into(),
                        prompt_tokens: usage.0,
                        output_tokens: usage.1,
                    },
                )
            }
            Err(failure) => self.fail(failure, session),
        }
    }

    fn handle_cancel(
        &mut self,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        self.engine.cancel();
        // The active stream (if any) ends cancelled via its own infer
        // answer; an idle cancel is an immediate cancelled terminal.
        let (wg, hg, profile) = self.id();
        self.send(
            session,
            WorkerFrameV1::BackendTerminal {
                worker_generation: wg,
                host_generation: hg,
                backend_profile: profile,
                stream_id: [0; 16],
                reason: "cancelled".into(),
                prompt_tokens: 0,
                output_tokens: 0,
            },
        )
    }

    fn health(&self) -> WorkerFrameV1 {
        let (wg, hg, profile) = self.id();
        WorkerFrameV1::BackendHealth {
            worker_generation: wg,
            host_generation: hg,
            backend_profile: profile,
        }
    }

    fn fail(
        &mut self,
        failure: EngineFailure,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
    ) -> Result<(), ProtocolError> {
        match failure {
            EngineFailure::Crash => {
                // No error frame: drop the wire like a dead process.
                Err(ProtocolError::Malformed)
            }
            EngineFailure::Native(code, detail) => {
                let (wg, hg, profile) = self.id();
                self.send(
                    session,
                    WorkerFrameV1::BackendError {
                        worker_generation: wg,
                        host_generation: hg,
                        backend_profile: profile,
                        code,
                        detail,
                    },
                )
            }
        }
    }

    fn id(&self) -> ([u8; 16], [u8; 16], String) {
        (
            self.identity.worker_generation,
            self.identity.host_generation,
            self.identity.backend_profile.clone(),
        )
    }

    fn send(
        &mut self,
        session: &mut runne_inference_protocol::Session<WorkerFrameV1>,
        frame: WorkerFrameV1,
    ) -> Result<(), ProtocolError> {
        let wire_bytes = session.encode(&frame)?;
        self.wire.send_frame(&wire_bytes)
    }
}

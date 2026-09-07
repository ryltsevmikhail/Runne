//! Deterministic fake backend (feature `backend-fake`): emits configured
//! chunks, usage and tool-proposal fixtures with controllable crash
//! points. Conformance/tests only — never satisfies the real-backend
//! qualification gate.

use crate::backend::{BackendConfig, BackendPort, GenerationCtx, LoadRequest, LoadedModel};
use crate::error::HostError;
use runne_inference_protocol::MessageV1;

#[derive(Default)]
pub struct FakeBackend {
    config: BackendConfig,
    loaded: Option<LoadedModel>,
}

impl FakeBackend {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            config,
            loaded: None,
        }
    }
}

impl BackendPort for FakeBackend {
    fn load(&mut self, req: &LoadRequest) -> Result<LoadedModel, HostError> {
        // Deterministic "inspection": the descriptor must read back the
        // declared GGUF magic; bytes are untrusted but never executed.
        let mut magic = [0u8; 4];
        use rustix::fs::SeekFrom;
        rustix::fs::seek(&req.artifact, SeekFrom::Start(0)).map_err(|_| HostError::CorruptModel)?;
        let n = rustix::io::read(&req.artifact, &mut magic).map_err(|_| HostError::CorruptModel)?;
        if n != 4 {
            return Err(HostError::CorruptModel);
        }
        rustix::fs::seek(&req.artifact, SeekFrom::Start(0)).map_err(|_| HostError::CorruptModel)?;
        if &magic != b"GGUF" {
            return Err(HostError::CorruptModel);
        }
        let loaded = LoadedModel {
            model_identity: req.model_identity.clone(),
            load_id: req.load_id,
        };
        self.loaded = Some(loaded.clone());
        Ok(loaded)
    }

    fn generate(&mut self, ctx: &GenerationCtx) -> Result<Vec<MessageV1>, HostError> {
        if self.loaded.is_none() {
            return Err(HostError::ModelNotLoaded);
        }
        let mut out = Vec::new();
        for (i, chunk) in self.config.chunks.iter().enumerate() {
            if Some(i) == self.config.crash_after {
                return Err(HostError::CorruptModel);
            }
            out.push(stream_item(ctx, i, "text", chunk.as_bytes()));
            if Some(i + 1) == self.config.tool_proposal_after {
                out.push(stream_item(
                    ctx,
                    i + 1,
                    "tool_proposal",
                    br#"{"name":"t","args":{}}"#,
                ));
            }
        }
        out.push(usage_item(ctx));
        out.push(finish_item(ctx));
        Ok(out)
    }

    fn cancel(&mut self) {}

    fn unload(&mut self) -> Result<(), HostError> {
        self.loaded = None;
        Ok(())
    }
}

fn stream_item(ctx: &GenerationCtx, seq: usize, kind: &str, payload: &[u8]) -> MessageV1 {
    MessageV1::StreamItem {
        generation_id: ctx.generation_id,
        attempt_id: ctx.attempt_id,
        stream_id: ctx.stream_id,
        stream_sequence: seq as u64,
        kind: kind.to_string(),
        payload: payload.to_vec(),
    }
}

fn usage_item(ctx: &GenerationCtx) -> MessageV1 {
    stream_item(ctx, usize::MAX - 2, "usage", b"{}")
}

fn finish_item(ctx: &GenerationCtx) -> MessageV1 {
    stream_item(ctx, usize::MAX - 1, "finish", b"stop")
}

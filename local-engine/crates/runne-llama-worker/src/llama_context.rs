//! llama.cpp engine: one verified model, per-request context, seeded
//! deterministic sampling, bounded output. CPU profile forces zero GPU
//! layers; there is no accelerator fallback.

use crate::engine::{EngineBackend, EngineFailure, EngineItem, EngineOutcome, EngineResult};
use crate::llama_model::{LoadedLlama, load_verified};
use crate::usage::TokenUsage;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::AddBos;
use llama_cpp_2::sampling::LlamaSampler;
use runne_inference_protocol::{WorkerBackendConfig, WorkerErrorCode, WorkerLoad};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct LlamaEngine {
    backend: std::sync::Arc<LlamaBackend>,
    loaded: Option<LoadedLlama>,
    config: WorkerBackendConfig,
    cancelled: AtomicBool,
}

/// Process-wide llama.cpp backend singleton (one per process by contract).
static BACKEND: std::sync::OnceLock<std::result::Result<std::sync::Arc<LlamaBackend>, String>> =
    std::sync::OnceLock::new();

fn shared_backend() -> std::result::Result<std::sync::Arc<LlamaBackend>, EngineFailure> {
    BACKEND
        .get_or_init(|| {
            LlamaBackend::init()
                .map(std::sync::Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| EngineFailure::Native(WorkerErrorCode::LoadFailed, e))
}

impl LlamaEngine {
    /// llama.cpp allows exactly one backend per process: it is created
    /// once (process-wide singleton) and reused for every load/infer.
    pub fn new() -> Result<Self, EngineFailure> {
        Ok(Self {
            backend: shared_backend()?,
            loaded: None,
            config: WorkerBackendConfig::default(),
            cancelled: AtomicBool::new(false),
        })
    }

    fn native(e: (WorkerErrorCode, String)) -> EngineFailure {
        EngineFailure::Native(e.0, e.1)
    }
}

impl EngineBackend for LlamaEngine {
    fn load(
        &mut self,
        load: &WorkerLoad,
        config: &WorkerBackendConfig,
        artifact: OwnedFd,
    ) -> EngineResult<()> {
        let loaded = load_verified(&self.backend, &artifact, load, config)?;
        self.loaded = Some(loaded);
        self.config = config.clone();
        self.cancelled.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn infer(
        &mut self,
        _generation_id: [u8; 16],
        _attempt_id: [u8; 16],
        _stream_id: [u8; 16],
        prompt: &str,
    ) -> EngineResult<(Vec<EngineItem>, EngineOutcome)> {
        let Some(loaded) = self.loaded.as_ref() else {
            return Err(EngineFailure::Native(
                WorkerErrorCode::LoadFailed,
                "no model".into(),
            ));
        };
        let LoadedLlama { model, .. } = loaded;
        let backend = &self.backend;
        let max_output = self.config.output_max_tokens.max(1) as usize;
        let tokens = model
            .str_to_token(prompt, AddBos::Always)
            .map_err(|e| Self::native((WorkerErrorCode::ContextExceeded, e.to_string())))?;
        if tokens.is_empty() {
            return Err(EngineFailure::Native(
                WorkerErrorCode::ContextExceeded,
                format!(
                    "tokenizer produced 0 tokens for prompt of {} bytes",
                    prompt.len()
                ),
            ));
        }
        if tokens.len() as u64 > u64::from(self.config.context_max_tokens) {
            return Err(EngineFailure::Native(
                WorkerErrorCode::ContextExceeded,
                format!("prompt {} tokens", tokens.len()),
            ));
        }
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(
                self.config.context_max_tokens.max(1),
            ))
            .with_n_threads(i32::from(self.config.threads.max(1) as i16));
        let mut ctx = model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| Self::native((WorkerErrorCode::LoadFailed, e.to_string())))?;
        let mut batch = LlamaBatch::new(tokens.len().max(1), 1);
        for (i, &token) in tokens.iter().enumerate() {
            batch
                .add(token, i as i32, &[0], i + 1 == tokens.len())
                .map_err(|e| Self::native((WorkerErrorCode::Internal, e.to_string())))?;
        }
        ctx.decode(&mut batch)
            .map_err(|e| Self::native((WorkerErrorCode::Internal, e.to_string())))?;
        let mut sampler = LlamaSampler::chain_simple([LlamaSampler::dist(self.config.seed)]);
        // Positions continue after the prompt: KV cache requires strictly
        // consecutive positions across the whole sequence.
        let mut next_pos = tokens.len() as i32;
        // One decoder for the whole run: split multi-byte characters
        // flush on the following token instead of corrupting.
        let mut decoder = encoding_rs::UTF_8.new_decoder();
        let mut items = Vec::new();
        let mut produced = 0usize;
        loop {
            if self.cancelled.load(Ordering::SeqCst) {
                self.cancelled.store(false, Ordering::SeqCst);
                return Ok((items, EngineOutcome::Cancelled));
            }
            let token = sampler.sample(&ctx, -1);
            if model.is_eog_token(token) {
                break;
            }
            let piece = model
                .token_to_piece(token, &mut decoder, false, None)
                .map_err(|e| Self::native((WorkerErrorCode::Internal, e.to_string())))?;
            items.push(EngineItem::Text(piece));
            produced += 1;
            if produced >= max_output {
                break;
            }
            let mut next = LlamaBatch::new(1, 1);
            next.add(token, next_pos, &[0], true)
                .map_err(|e| Self::native((WorkerErrorCode::Internal, e.to_string())))?;
            next_pos += 1;
            ctx.decode(&mut next)
                .map_err(|e| Self::native((WorkerErrorCode::Internal, e.to_string())))?;
        }
        let usage = TokenUsage::new(tokens.len() as u64, produced as u64);
        items.push(EngineItem::Usage {
            prompt_tokens: usage.prompt_tokens,
            output_tokens: usage.output_tokens,
        });
        items.push(EngineItem::Finish);
        Ok((items, EngineOutcome::Stopped))
    }

    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn unload(&mut self) -> EngineResult<()> {
        self.loaded = None;
        Ok(())
    }
}

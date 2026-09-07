//! llama.cpp model loading: digest-verified intake over the granted
//! read-only descriptor, forced-zero GPU layers for the CPU profile.
//! The descriptor is addressed through `/dev/fd/<n>` because llama.cpp
//! loads by path; the digest gate runs BEFORE any native load.

use crate::engine::EngineFailure;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::{LlamaModel, params::LlamaModelParams};
use runne_inference_protocol::{WorkerBackendConfig, WorkerErrorCode, WorkerLoad};
use sha2::Digest as _;
use std::os::fd::AsRawFd;
use std::path::Path;

pub struct LoadedLlama {
    pub model: LlamaModel,
    pub model_identity: String,
    pub load_id: [u8; 16],
}

/// Streams the artifact through sha256, enforces the declared length,
/// then loads it into llama.cpp. Memory stays bounded; size is capped
/// by the declared `byte_length`.
pub fn load_verified(
    backend: &LlamaBackend,
    artifact: &std::os::fd::OwnedFd,
    load: &WorkerLoad,
    config: &WorkerBackendConfig,
) -> Result<LoadedLlama, EngineFailure> {
    let (digest, actual_len) = stream_digest(artifact).map_err(native)?;
    // /dev/fd/N dups the descriptor on open, sharing the file offset:
    // rewind it so llama.cpp reads the artifact from the beginning.
    rustix::fs::seek(artifact, rustix::fs::SeekFrom::Start(0))
        .map_err(|e| native((WorkerErrorCode::LoadFailed, format!("rewind: {e}"))))?;
    if actual_len != load.byte_length {
        return Err(EngineFailure::Native(
            WorkerErrorCode::LengthMismatch,
            format!("declared {} got {}", load.byte_length, actual_len),
        ));
    }
    let digest = format!("sha256:{}", hex(&digest));
    if digest != load.artifact_digest {
        return Err(EngineFailure::Native(
            WorkerErrorCode::DigestMismatch,
            digest,
        ));
    }
    // CPU profile pins zero GPU layers; Metal activation requires its
    // own distinct profile identity and evidence (no fallback).
    let mut params = LlamaModelParams::default();
    if config.gpu_layers == 0 {
        params = params.with_n_gpu_layers(0);
    }
    // The descriptor is addressed through /dev/fd/N: mmap of that path is
    // not guaranteed (and fails on some macOS kernels), so force the
    // plain read() load path.
    params = params.with_use_mmap(false);
    let path = format!("/dev/fd/{}", artifact.as_raw_fd());
    let model = LlamaModel::load_from_file(backend, Path::new(&path), &params)
        .map_err(|e| native((WorkerErrorCode::LoadFailed, e.to_string())))?;
    Ok(LoadedLlama {
        model,
        model_identity: load.model_identity.clone(),
        load_id: load.load_id,
    })
}

fn native(e: (WorkerErrorCode, String)) -> EngineFailure {
    EngineFailure::Native(e.0, e.1)
}

fn stream_digest(fd: &std::os::fd::OwnedFd) -> Result<([u8; 32], u64), (WorkerErrorCode, String)> {
    let mut hasher = sha2::Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = rustix::io::read(fd, &mut buf)
            .map_err(|e| (WorkerErrorCode::LoadFailed, format!("artifact read: {e}")))?;
        if n == 0 {
            return Ok((hasher.finalize().into(), total));
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

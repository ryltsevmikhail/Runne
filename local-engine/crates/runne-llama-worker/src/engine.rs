//! Engine abstraction behind the worker session: llama.cpp is one
//! implementation (feature `backend-llama-cpp`); the deterministic
//! `FakeEngine` backs tests and conformance runs without native code.

use runne_inference_protocol::{WorkerBackendConfig, WorkerErrorCode, WorkerLoad};
use std::os::fd::OwnedFd;

/// One normalized engine output item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineItem {
    Text(String),
    Usage {
        prompt_tokens: u64,
        output_tokens: u64,
    },
    Finish,
}

/// Terminal disposition of one infer call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineOutcome {
    Stopped,
    Cancelled,
}

/// Engine failure: a reportable native error (typed protocol code) or
/// a crash. A crash produces NO protocol frame — the serve loop drops
/// the wire, which the host experiences exactly like process death.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineFailure {
    Native(WorkerErrorCode, String),
    Crash,
}

pub type EngineResult<T> = Result<T, EngineFailure>;

/// Bounded, deterministic engine surface. `load` receives exactly one
/// read-only artifact descriptor and must verify digest/length itself.
pub trait EngineBackend {
    fn load(
        &mut self,
        load: &WorkerLoad,
        config: &WorkerBackendConfig,
        artifact: OwnedFd,
    ) -> EngineResult<()>;
    fn infer(
        &mut self,
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
        prompt: &str,
    ) -> EngineResult<(Vec<EngineItem>, EngineOutcome)>;
    fn cancel(&mut self);
    fn unload(&mut self) -> EngineResult<()>;
}

/// Deterministic fake: verifies digest+length honestly, emits the
/// configured chunks, supports crash injection and forced-OOM codes.
pub struct FakeEngine {
    pub chunks: Vec<String>,
    /// Crashes (abrupt wire drop) after N emitted text items.
    pub crash_after: Option<usize>,
    /// Returns a Memory error after N emitted text items.
    pub oom_after: Option<usize>,
    loaded: Option<String>,
    cancelled: bool,
}

impl FakeEngine {
    pub fn new(chunks: Vec<String>) -> Self {
        Self {
            chunks,
            crash_after: None,
            oom_after: None,
            loaded: None,
            cancelled: false,
        }
    }

    pub fn crash_after(mut self, n: usize) -> Self {
        self.crash_after = Some(n);
        self
    }

    pub fn oom_after(mut self, n: usize) -> Self {
        self.oom_after = Some(n);
        self
    }
}

impl EngineBackend for FakeEngine {
    fn load(
        &mut self,
        load: &WorkerLoad,
        _config: &WorkerBackendConfig,
        artifact: OwnedFd,
    ) -> EngineResult<()> {
        let bytes = read_bounded(&artifact, 64 * 1024 * 1024)
            .map_err(|e| EngineFailure::Native(WorkerErrorCode::LoadFailed, e))?;
        if bytes.len() as u64 != load.byte_length {
            return Err(EngineFailure::Native(
                WorkerErrorCode::LengthMismatch,
                format!("declared {} got {}", load.byte_length, bytes.len()),
            ));
        }
        use sha2::Digest as _;
        let digest = format!("sha256:{}", hex(&sha2::Sha256::digest(&bytes)));
        if digest != load.artifact_digest {
            return Err(EngineFailure::Native(
                WorkerErrorCode::DigestMismatch,
                digest,
            ));
        }
        self.loaded = Some(load.model_identity.clone());
        Ok(())
    }

    fn infer(
        &mut self,
        _generation_id: [u8; 16],
        _attempt_id: [u8; 16],
        _stream_id: [u8; 16],
        _prompt: &str,
    ) -> EngineResult<(Vec<EngineItem>, EngineOutcome)> {
        if self.loaded.is_none() {
            return Err(EngineFailure::Native(
                WorkerErrorCode::LoadFailed,
                "no model".into(),
            ));
        }
        let mut items = Vec::new();
        for (emitted, chunk) in self.chunks.iter().enumerate() {
            if self.cancelled {
                return Ok((items, EngineOutcome::Cancelled));
            }
            if self.crash_after == Some(emitted) {
                return Err(EngineFailure::Crash);
            }
            if self.oom_after == Some(emitted) {
                return Err(EngineFailure::Native(
                    WorkerErrorCode::Memory,
                    "forced oom".into(),
                ));
            }
            items.push(EngineItem::Text(chunk.clone()));
        }
        let total = self.chunks.join("").len() as u64;
        items.push(EngineItem::Usage {
            prompt_tokens: total,
            output_tokens: total,
        });
        if self.cancelled {
            return Ok((items, EngineOutcome::Cancelled));
        }
        items.push(EngineItem::Finish);
        self.cancelled = false;
        Ok((items, EngineOutcome::Stopped))
    }

    fn cancel(&mut self) {
        self.cancelled = true;
    }

    fn unload(&mut self) -> EngineResult<()> {
        self.loaded = None;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Reads at most `cap` bytes from the descriptor; larger artifacts are
/// rejected (bounded intake; no allocation from untrusted counts).
fn read_bounded(fd: &OwnedFd, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = rustix::io::read(fd, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > cap {
            return Err("artifact exceeds bounded intake".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
}

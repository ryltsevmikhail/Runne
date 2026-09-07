//! `LocalProviderAdapter`: ProviderPort implementation over the fake
//! host session, broker and catalog. Prepare is effect-free; dispatch
//! requires the exact consumed permit; streams are ordered and
//! attempt-scoped; reconciliation is evidence-driven (Absent/Settled/
//! Uncertain, never silent redispatch).

use crate::error::ProviderError;
use crate::port::{
    DispatchRequest, ProviderCall, ProviderPort, ProviderStream, Reconciliation, StreamItem,
};
use crate::prepared::PreparedRequest;
use runne_inference_host::backend::{BackendConfig, BackendPort, LoadRequest};
use runne_inference_host::{FakeBackend, HostSession};
use runne_inference_protocol::{Direction, Session};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Injected application-owned ports (Task 8 interfaces).
pub trait LocalExecutionPermitPort {
    /// Returns Some(()) when the exact attempt was already admitted.
    fn resolve_consumed(&self, attempt_id: &[u8; 16]) -> Result<bool, ProviderError>;
}

pub trait LocalUsageSettlementPort {
    /// Idempotent settlement: second call for the same attempt is a no-op.
    fn settle_once(&mut self, attempt_id: &[u8; 16], input_tokens: u64, output_tokens: u64);
}

/// Minimal adapter context: model identity resolution via catalog digest.
pub struct LocalProviderAdapter<PermitPortT, SettlePortT> {
    pub(crate) permit_port: PermitPortT,
    pub(crate) settlement: SettlePortT,
    pub(crate) known_manifests: std::collections::BTreeMap<String, String>, // digest -> model_identity
    pub(crate) streams: BTreeMap<[u8; 16], ProviderStream>,
    pub(crate) settled: std::collections::BTreeSet<[u8; 16]>,
    /// Attempts with an authenticated terminal stream item (the ONLY
    /// Settled input — settlement alone is not completion).
    pub(crate) terminal_evidence: std::collections::BTreeSet<[u8; 16]>,
    /// Markers for reconciliation when terminal evidence is absent.
    pub(crate) dispatched_no_evidence: std::collections::BTreeSet<[u8; 16]>,
    /// Streams with a recorded cancel intent.
    pub(crate) cancelling: std::collections::BTreeSet<[u8; 16]>,
    /// Content-addressed blob dir of the model store.
    pub(crate) blobs_dir: PathBuf,
}

impl<
    PermitPortT: LocalExecutionPermitPort + Send + Sync,
    SettlePortT: LocalUsageSettlementPort + Send + Sync,
> ProviderPort for LocalProviderAdapter<PermitPortT, SettlePortT>
{
    /// Effect-free: resolves the exact installed identity by manifest
    /// digest; no host launch, no catalog mutation.
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, ProviderError> {
        let identity = self
            .known_manifests
            .get(&call.manifest_digest)
            .ok_or(ProviderError::ArtifactNotInstalled)?;
        // Render digest: canonical hash over call identity + bound.
        let mut material = Vec::new();
        material.extend_from_slice(&call.call_id);
        material.extend_from_slice(identity.as_bytes());
        material.extend_from_slice(&call.max_output_tokens.to_be_bytes());
        for (role, text) in &call.inputs {
            material.extend_from_slice(role.as_bytes());
            material.extend_from_slice(text.as_bytes());
        }
        // Sampling: two-level validation, effective digest feeds the
        // attempt identity (changed sampling = new attempt).
        let effective = crate::sampling::effective_sampling(
            &call.extension,
            crate::sampling::ProfileDefaults::v1(),
            crate::sampling::BackendBounds::llama_cpu_v1(),
        )
        .map_err(ProviderError::Sampling)?;
        let sampling_digest = effective.digest();
        material.extend_from_slice(sampling_digest.as_bytes());
        // Structured-output: in-subset schema digest joins the attempt
        // identity; out-of-subset schema rejects before any effect.
        let structured = crate::structured::StructuredRequest::from_extension(&call.extension)
            .map_err(ProviderError::Structured)?;
        if let Some(sr) = &structured {
            material.extend_from_slice(sr.schema_digest.as_bytes());
        }
        use sha2::{Digest as _, Sha256};
        let render_digest = hex::encode(Sha256::digest(&material));
        let prompt = call
            .inputs
            .iter()
            .map(|(role, text)| format!("{role}: {text}"))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(PreparedRequest {
            call_id: call.call_id,
            model_identity: identity.clone(),
            render_digest,
            sampling_digest,
            structured: structured.map(|sr| sr.schema_digest),
            prompt,
        })
    }

    /// Admitted dispatch: permit must be already-consumed for this exact
    /// attempt; produces the ordered deterministic stream via the fake
    /// host backend and settles usage exactly once.
    fn dispatch(
        &mut self,
        prepared: &PreparedRequest,
        request: &DispatchRequest,
    ) -> Result<ProviderStream, ProviderError> {
        if request.prepared_call_id != prepared.call_id {
            return Err(ProviderError::FrameMismatch);
        }
        if self.settled.contains(&request.attempt_id) {
            return Err(ProviderError::AttemptConflict);
        }
        if !self.permit_port.resolve_consumed(&request.attempt_id)? {
            return Err(ProviderError::FrameMismatch);
        }
        // Deterministic streaming via the in-process fake host.
        let keys = Session::new(
            runne_inference_protocol::SessionKeys::derive(
                &runne_inference_protocol::LaunchSecret::from_bytes(&[0x42; 32]),
                b"hello",
                b"welcome",
                &runne_inference_protocol::ContextMaterial {
                    channel: request.stream_id,
                    epoch: generation_epoch(request.generation_id),
                    tag: [0, 0, 0],
                },
                runne_inference_protocol::SESSION_PURPOSE.as_bytes(),
            )
            .expect("keys"),
            request.stream_id,
            0,
            Direction::H2c,
            64 * 1024,
        );
        let mut host = HostSession::new(
            keys,
            std::os::unix::net::UnixStream::pair().expect("pair").0,
            FakeBackend::new(BackendConfig {
                chunks: vec!["answer".into()],
                tool_proposal_after: None,
                crash_after: None,
            }),
        );
        // The artifact opens from the catalog blob store by digest —
        // never from a caller-supplied path.
        let blob_path = self.blobs_dir.join(
            request
                .artifact_digest
                .strip_prefix("sha256:")
                .unwrap_or(&request.artifact_digest),
        );
        let file =
            std::fs::File::open(blob_path).map_err(|_| ProviderError::ArtifactNotInstalled)?;
        let byte_length = file.metadata().map(|m| m.len()).unwrap_or(0);
        let load = LoadRequest {
            model_identity: prepared.model_identity.clone(),
            load_id: request.stream_id,
            artifact: file,
            artifact_digest: request.artifact_digest.clone(),
            byte_length,
            config: BackendConfig::default(),
        };
        host.backend_mut().load(&load)?;
        host.mark_loaded(prepared.model_identity.clone(), request.stream_id);
        let items = runne_inference_host::generate::stream_generation(
            &mut host,
            request.generation_id,
            request.attempt_id,
            request.stream_id,
            &prepared.prompt,
        )?;

        // Normalize text/usage/finish only, strict sequence from zero.
        let mut stream = ProviderStream {
            stream_id: request.stream_id,
            cursor: 0,
            items: Vec::new(),
            finished: false,
        };
        let mut seq_seen = std::collections::BTreeSet::new();
        for item in items {
            if let runne_inference_protocol::MessageV1::StreamItem {
                stream_sequence,
                kind,
                payload,
                ..
            } = item
            {
                if !seq_seen.insert(stream_sequence) {
                    return Err(ProviderError::MalformedStream);
                }
                match kind.as_str() {
                    "text" => stream.items.push(StreamItem::Text {
                        seq: stream_sequence,
                        text: String::from_utf8_lossy(&payload).to_string(),
                    }),
                    "usage" => {
                        // Usage settles once through the settlement port.
                        if !self.settled.contains(&request.attempt_id) {
                            self.settlement.settle_once(&request.attempt_id, 0, 0);
                            self.settled.insert(request.attempt_id);
                        }
                    }
                    "finish" => {
                        stream.finished = true;
                        stream.items.push(StreamItem::Finished {
                            seq: stream_sequence,
                            reason: "stop".into(),
                        });
                    }
                    _ => {
                        return Err(ProviderError::MalformedStream);
                    }
                }
            }
        }
        if !stream.finished {
            return Err(ProviderError::MalformedStream);
        }
        if stream.finished {
            self.terminal_evidence.insert(request.attempt_id);
        }
        self.streams.insert(stream.stream_id, stream.clone());
        Ok(stream)
    }

    /// Ordered, attempt-scoped cursor read.
    fn next(
        &mut self,
        stream_id: &[u8; 16],
        cursor: u64,
    ) -> Result<Option<StreamItem>, ProviderError> {
        let stream = self
            .streams
            .get(stream_id)
            .ok_or(ProviderError::FrameMismatch)?;
        if stream.finished && cursor >= stream.items.len() as u64 {
            return Ok(None);
        }
        Ok(stream.items.get(cursor as usize).cloned())
    }

    /// Local cancel receipt: `Requested` once, `AlreadyRequested`
    /// after. Terminal evidence arrives through the stream; a receipt
    /// is never completion.
    fn cancel(
        &mut self,
        stream_id: &[u8; 16],
    ) -> Result<crate::port::CancelDisposition, ProviderError> {
        if !self.streams.contains_key(stream_id) {
            return Err(ProviderError::FrameMismatch);
        }
        if self.cancelling.insert(*stream_id) {
            Ok(crate::port::CancelDisposition::Requested)
        } else {
            Ok(crate::port::CancelDisposition::AlreadyRequested)
        }
    }

    /// Evidence-driven reconciliation: terminal stream item → Settled;
    /// dispatched (even usage-settled) without terminal evidence →
    /// Uncertain; never dispatched → Absent.
    fn reconcile(&mut self, attempt_id: &[u8; 16]) -> Result<Reconciliation, ProviderError> {
        if self.terminal_evidence.contains(attempt_id) {
            return Ok(Reconciliation::Settled);
        }
        if self.settled.contains(attempt_id) || self.dispatched_no_evidence.contains(attempt_id) {
            return Ok(Reconciliation::Uncertain);
        }
        Ok(Reconciliation::Absent)
    }
}

impl<
    PermitPortT: LocalExecutionPermitPort + Send + Sync,
    SettlePortT: LocalUsageSettlementPort + Send + Sync,
> LocalProviderAdapter<PermitPortT, SettlePortT>
{
    /// Records a dispatch whose acknowledgement was lost (uncertain).
    pub fn mark_dispatch_ambiguous(&mut self, attempt_id: [u8; 16]) {
        self.dispatched_no_evidence.insert(attempt_id);
    }
}

/// Host generation ids are 16 bytes; the expand context uses the first 8.
fn generation_epoch(generation_id: [u8; 16]) -> [u8; 8] {
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&generation_id[..8]);
    epoch
}

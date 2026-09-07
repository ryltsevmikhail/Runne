//! Strict decoder for worker-catalog CBOR bodies.

use crate::backend::{WorkerBackendConfig, WorkerErrorCode, WorkerFrameV1, WorkerLoad};
use crate::cbor::Cbor;
use crate::error::ProtocolError;

struct Fields<'a> {
    map: &'a std::collections::BTreeMap<Vec<u8>, Cbor>,
}

impl<'a> Fields<'a> {
    fn bytes(&self, key: &str) -> Result<Vec<u8>, ProtocolError> {
        match self.map.get(key.as_bytes()) {
            Some(Cbor::Bytes(value)) => Ok(value.clone()),
            _ => Err(ProtocolError::UnknownField),
        }
    }
    fn text(&self, key: &str) -> Result<String, ProtocolError> {
        match self.map.get(key.as_bytes()) {
            Some(Cbor::Text(value)) => Ok(value.clone()),
            _ => Err(ProtocolError::UnknownField),
        }
    }
    fn uint(&self, key: &str) -> Result<u64, ProtocolError> {
        match self.map.get(key.as_bytes()) {
            Some(Cbor::Unsigned(value)) => Ok(*value),
            _ => Err(ProtocolError::UnknownField),
        }
    }
    fn arr16(&self, key: &str) -> Result<[u8; 16], ProtocolError> {
        self.bytes(key)?
            .try_into()
            .map_err(|_| ProtocolError::Malformed)
    }
    fn u32_of(&self, key: &str) -> Result<u32, ProtocolError> {
        u32::try_from(self.uint(key)?).map_err(|_| ProtocolError::Malformed)
    }
    fn triple(&self) -> Result<([u8; 16], [u8; 16], String), ProtocolError> {
        Ok((self.arr16("wg")?, self.arr16("hg")?, self.text("profile")?))
    }
    fn config(&self) -> Result<WorkerBackendConfig, ProtocolError> {
        Ok(WorkerBackendConfig {
            context_max_tokens: self.u32_of("ctx")?,
            output_max_tokens: self.u32_of("out")?,
            gpu_layers: self.u32_of("gpu")?,
            threads: self.u32_of("thr")?,
            seed: self.u32_of("seed")?,
        })
    }
    fn load(&self) -> Result<WorkerLoad, ProtocolError> {
        Ok(WorkerLoad {
            model_identity: self.text("model_identity")?,
            load_id: self.arr16("load_id")?,
            artifact_digest: self.text("digest")?,
            byte_length: self.uint("len")?,
            load_fence: self.arr16("fence")?,
        })
    }
}

fn checked_item_kind(kind: &str) -> Result<(), ProtocolError> {
    crate::backend::WORKER_ITEM_KINDS
        .contains(&kind)
        .then_some(())
        .ok_or(ProtocolError::Malformed)
}

fn checked_reason(reason: &str) -> Result<(), ProtocolError> {
    crate::backend::WORKER_TERMINAL_REASONS
        .contains(&reason)
        .then_some(())
        .ok_or(ProtocolError::Malformed)
}

pub fn decode_worker_body(type_name: &str, body: &Cbor) -> Result<WorkerFrameV1, ProtocolError> {
    let Cbor::Map(map) = body else {
        return Err(ProtocolError::Malformed);
    };
    if !matches!(
        type_name,
        "backend_load"
            | "backend_loaded"
            | "backend_infer"
            | "backend_item"
            | "backend_cancel"
            | "backend_unload"
            | "backend_health"
            | "backend_terminal"
            | "backend_error"
    ) {
        return Err(ProtocolError::UnknownType);
    }
    let fields = Fields { map };
    let (worker_generation, host_generation, backend_profile) = fields.triple()?;
    match type_name {
        "backend_load" => Ok(WorkerFrameV1::BackendLoad {
            worker_generation,
            host_generation,
            backend_profile,
            load: fields.load()?,
            config: fields.config()?,
        }),
        "backend_loaded" => Ok(WorkerFrameV1::BackendLoaded {
            worker_generation,
            host_generation,
            backend_profile,
            load_id: fields.arr16("load_id")?,
            model_identity: fields.text("model_identity")?,
        }),
        "backend_infer" => Ok(WorkerFrameV1::BackendInfer {
            worker_generation,
            host_generation,
            backend_profile,
            generation_id: fields.arr16("generation_id")?,
            attempt_id: fields.arr16("attempt_id")?,
            stream_id: fields.arr16("stream_id")?,
            prompt: fields.text("prompt")?,
        }),
        "backend_item" => decode_item(fields, worker_generation, host_generation, backend_profile),
        "backend_cancel" => Ok(WorkerFrameV1::BackendCancel {
            worker_generation,
            host_generation,
            backend_profile,
            cancel_id: fields.arr16("cancel_id")?,
        }),
        "backend_unload" => Ok(WorkerFrameV1::BackendUnload {
            worker_generation,
            host_generation,
            backend_profile,
            load_id: fields.arr16("load_id")?,
        }),
        "backend_health" => Ok(WorkerFrameV1::BackendHealth {
            worker_generation,
            host_generation,
            backend_profile,
        }),
        "backend_terminal" => {
            decode_terminal(fields, worker_generation, host_generation, backend_profile)
        }
        "backend_error" => {
            decode_error(fields, worker_generation, host_generation, backend_profile)
        }
        _ => Err(ProtocolError::UnknownType),
    }
}

fn decode_item(
    fields: Fields<'_>,
    worker_generation: [u8; 16],
    host_generation: [u8; 16],
    backend_profile: String,
) -> Result<WorkerFrameV1, ProtocolError> {
    let kind = fields.text("kind")?;
    checked_item_kind(&kind)?;
    Ok(WorkerFrameV1::BackendItem {
        worker_generation,
        host_generation,
        backend_profile,
        stream_id: fields.arr16("stream_id")?,
        stream_sequence: fields.uint("seq")?,
        kind,
        payload: fields.bytes("payload")?,
    })
}

fn decode_terminal(
    fields: Fields<'_>,
    worker_generation: [u8; 16],
    host_generation: [u8; 16],
    backend_profile: String,
) -> Result<WorkerFrameV1, ProtocolError> {
    let reason = fields.text("reason")?;
    checked_reason(&reason)?;
    Ok(WorkerFrameV1::BackendTerminal {
        worker_generation,
        host_generation,
        backend_profile,
        stream_id: fields.arr16("stream_id")?,
        reason,
        prompt_tokens: fields.uint("prompt_tokens")?,
        output_tokens: fields.uint("output_tokens")?,
    })
}

fn decode_error(
    fields: Fields<'_>,
    worker_generation: [u8; 16],
    host_generation: [u8; 16],
    backend_profile: String,
) -> Result<WorkerFrameV1, ProtocolError> {
    let code: WorkerErrorCode = fields
        .text("code")?
        .parse()
        .map_err(|_| ProtocolError::Malformed)?;
    let detail = fields.text("detail")?;
    if detail.len() > WorkerFrameV1::MAX_DETAIL_BYTES {
        return Err(ProtocolError::Malformed);
    }
    Ok(WorkerFrameV1::BackendError {
        worker_generation,
        host_generation,
        backend_profile,
        code,
        detail,
    })
}

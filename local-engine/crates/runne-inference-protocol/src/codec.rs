//! Body codec and public catalog API (PROTOCOL.md §Message catalog).
pub use crate::protocol_body::{ProtocolBody, decode_body, encode_body};

use crate::cbor::Cbor;
use crate::error::ProtocolError;
use crate::message::MessageV1;

pub(crate) fn encode_message_body(message: &MessageV1) -> Cbor {
    let mut m = std::collections::BTreeMap::new();
    match message {
        MessageV1::Hello {
            client_nonce,
            runtime_identity,
            adapter_identity,
            backend_profile_id,
            model_identity,
        } => {
            m.insert(b"client_nonce".to_vec(), Cbor::Bytes(client_nonce.to_vec()));
            m.insert(
                b"runtime_identity".to_vec(),
                Cbor::Text(runtime_identity.clone()),
            );
            m.insert(
                b"adapter_identity".to_vec(),
                Cbor::Text(adapter_identity.clone()),
            );
            m.insert(
                b"backend_profile_id".to_vec(),
                Cbor::Text(backend_profile_id.clone()),
            );
            m.insert(
                b"model_identity".to_vec(),
                Cbor::Text(model_identity.clone()),
            );
        }
        MessageV1::Welcome {
            host_nonce,
            session_id,
            generation,
            host_identity,
            backend_profile_id,
            max_frame_bytes,
        } => {
            m.insert(b"host_nonce".to_vec(), Cbor::Bytes(host_nonce.to_vec()));
            m.insert(b"session_id".to_vec(), Cbor::Bytes(session_id.to_vec()));
            m.insert(b"generation".to_vec(), Cbor::Unsigned(*generation));
            m.insert(b"host_identity".to_vec(), Cbor::Text(host_identity.clone()));
            m.insert(
                b"backend_profile_id".to_vec(),
                Cbor::Text(backend_profile_id.clone()),
            );
            m.insert(
                b"max_frame_bytes".to_vec(),
                Cbor::Unsigned(*max_frame_bytes as u64),
            );
        }
        MessageV1::Ready { transcript_digest } => {
            m.insert(
                b"transcript_digest".to_vec(),
                Cbor::Bytes(transcript_digest.to_vec()),
            );
        }
        MessageV1::LoadModel {
            model_identity,
            load_id,
            artifact_digest,
            byte_length,
        } => {
            m.insert(
                b"model_identity".to_vec(),
                Cbor::Text(model_identity.clone()),
            );
            m.insert(b"load_id".to_vec(), Cbor::Bytes(load_id.to_vec()));
            m.insert(
                b"artifact_digest".to_vec(),
                Cbor::Text(artifact_digest.clone()),
            );
            m.insert(b"byte_length".to_vec(), Cbor::Unsigned(*byte_length));
        }
        MessageV1::GenerationRequest {
            generation_id,
            attempt_id,
            prepared_request_ref,
        } => {
            m.insert(
                b"generation_id".to_vec(),
                Cbor::Bytes(generation_id.to_vec()),
            );
            m.insert(b"attempt_id".to_vec(), Cbor::Bytes(attempt_id.to_vec()));
            m.insert(
                b"prepared_request_ref".to_vec(),
                Cbor::Text(prepared_request_ref.clone()),
            );
        }
        MessageV1::GenerationStarted {
            generation_id,
            attempt_id,
            stream_id,
        } => {
            m.insert(
                b"generation_id".to_vec(),
                Cbor::Bytes(generation_id.to_vec()),
            );
            m.insert(b"attempt_id".to_vec(), Cbor::Bytes(attempt_id.to_vec()));
            m.insert(b"stream_id".to_vec(), Cbor::Bytes(stream_id.to_vec()));
        }
        MessageV1::StreamItem {
            generation_id,
            attempt_id,
            stream_id,
            stream_sequence,
            kind,
            payload,
        } => {
            m.insert(
                b"generation_id".to_vec(),
                Cbor::Bytes(generation_id.to_vec()),
            );
            m.insert(b"attempt_id".to_vec(), Cbor::Bytes(attempt_id.to_vec()));
            m.insert(b"stream_id".to_vec(), Cbor::Bytes(stream_id.to_vec()));
            m.insert(
                b"stream_sequence".to_vec(),
                Cbor::Unsigned(*stream_sequence),
            );
            m.insert(b"kind".to_vec(), Cbor::Text(kind.clone()));
            m.insert(b"payload".to_vec(), Cbor::Bytes(payload.clone()));
        }
        MessageV1::StreamAck {
            stream_id,
            highest_sequence,
        } => {
            m.insert(b"stream_id".to_vec(), Cbor::Bytes(stream_id.to_vec()));
            m.insert(
                b"highest_sequence".to_vec(),
                Cbor::Unsigned(*highest_sequence),
            );
        }
        MessageV1::Cancel {
            generation_id,
            attempt_id,
            cancel_id,
        } => {
            m.insert(
                b"generation_id".to_vec(),
                Cbor::Bytes(generation_id.to_vec()),
            );
            m.insert(b"attempt_id".to_vec(), Cbor::Bytes(attempt_id.to_vec()));
            m.insert(b"cancel_id".to_vec(), Cbor::Bytes(cancel_id.to_vec()));
        }
        MessageV1::CancelAck {
            cancel_id,
            disposition,
        } => {
            m.insert(b"cancel_id".to_vec(), Cbor::Bytes(cancel_id.to_vec()));
            m.insert(b"disposition".to_vec(), Cbor::Text(disposition.clone()));
        }
        MessageV1::Health | MessageV1::DrainAck | MessageV1::ShutdownAck => {}
        MessageV1::HealthResult { state } => {
            m.insert(b"state".to_vec(), Cbor::Text(state.clone()));
        }
        MessageV1::Drain { deadline_ms } | MessageV1::Shutdown { deadline_ms } => {
            m.insert(b"deadline_ms".to_vec(), Cbor::Unsigned(*deadline_ms));
        }
        MessageV1::Reconcile {
            attempt_id,
            generation_id,
        } => {
            m.insert(b"attempt_id".to_vec(), Cbor::Bytes(attempt_id.to_vec()));
            m.insert(
                b"generation_id".to_vec(),
                Cbor::Bytes(generation_id.to_vec()),
            );
        }
        MessageV1::ReconcileResult { result } => {
            m.insert(b"result".to_vec(), Cbor::Text(result.clone()));
        }
        MessageV1::Error { code, detail } => {
            m.insert(b"code".to_vec(), Cbor::Text(code.clone()));
            m.insert(b"detail".to_vec(), Cbor::Text(detail.clone()));
        }
    }
    Cbor::Map(m)
}

pub(crate) fn decode_message_body(
    type_name: &str,
    body: &Cbor,
) -> Result<MessageV1, ProtocolError> {
    let Cbor::Map(map) = body else {
        return Err(ProtocolError::Malformed);
    };
    let bytes_of = |k: &str| -> Result<Vec<u8>, ProtocolError> {
        match map.get(k.as_bytes()) {
            Some(Cbor::Bytes(b)) => Ok(b.clone()),
            _ => Err(ProtocolError::UnknownField),
        }
    };
    let text_of = |k: &str| -> Result<String, ProtocolError> {
        match map.get(k.as_bytes()) {
            Some(Cbor::Text(s)) => Ok(s.clone()),
            _ => Err(ProtocolError::UnknownField),
        }
    };
    let uint_of = |k: &str| -> Result<u64, ProtocolError> {
        match map.get(k.as_bytes()) {
            Some(Cbor::Unsigned(u)) => Ok(*u),
            _ => Err(ProtocolError::UnknownField),
        }
    };
    let arr16 = |k: &str| -> Result<[u8; 16], ProtocolError> {
        bytes_of(k)?
            .try_into()
            .map_err(|_| ProtocolError::Malformed)
    };
    Ok(match type_name {
        "hello" => MessageV1::Hello {
            client_nonce: arr16("client_nonce")?,
            runtime_identity: text_of("runtime_identity")?,
            adapter_identity: text_of("adapter_identity")?,
            backend_profile_id: text_of("backend_profile_id")?,
            model_identity: text_of("model_identity")?,
        },
        "welcome" => MessageV1::Welcome {
            host_nonce: arr16("host_nonce")?,
            session_id: arr16("session_id")?,
            generation: uint_of("generation")?,
            host_identity: text_of("host_identity")?,
            backend_profile_id: text_of("backend_profile_id")?,
            max_frame_bytes: u32::try_from(uint_of("max_frame_bytes")?)
                .map_err(|_| ProtocolError::Malformed)?,
        },
        "ready" => MessageV1::Ready {
            transcript_digest: bytes_of("transcript_digest")?
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?,
        },
        "load_model" => MessageV1::LoadModel {
            model_identity: text_of("model_identity")?,
            load_id: arr16("load_id")?,
            artifact_digest: text_of("artifact_digest")?,
            byte_length: uint_of("byte_length")?,
        },
        "generation_request" => MessageV1::GenerationRequest {
            generation_id: arr16("generation_id")?,
            attempt_id: arr16("attempt_id")?,
            prepared_request_ref: text_of("prepared_request_ref")?,
        },
        "generation_started" => MessageV1::GenerationStarted {
            generation_id: arr16("generation_id")?,
            attempt_id: arr16("attempt_id")?,
            stream_id: arr16("stream_id")?,
        },
        "stream_item" => MessageV1::StreamItem {
            generation_id: arr16("generation_id")?,
            attempt_id: arr16("attempt_id")?,
            stream_id: arr16("stream_id")?,
            stream_sequence: uint_of("stream_sequence")?,
            kind: text_of("kind")?,
            payload: bytes_of("payload")?,
        },
        "stream_ack" => MessageV1::StreamAck {
            stream_id: arr16("stream_id")?,
            highest_sequence: uint_of("highest_sequence")?,
        },
        "cancel" => MessageV1::Cancel {
            generation_id: arr16("generation_id")?,
            attempt_id: arr16("attempt_id")?,
            cancel_id: arr16("cancel_id")?,
        },
        "cancel_ack" => MessageV1::CancelAck {
            cancel_id: arr16("cancel_id")?,
            disposition: text_of("disposition")?,
        },
        "health" => MessageV1::Health,
        "health_result" => MessageV1::HealthResult {
            state: text_of("state")?,
        },
        "drain" => MessageV1::Drain {
            deadline_ms: uint_of("deadline_ms")?,
        },
        "drain_ack" => MessageV1::DrainAck,
        "shutdown" => MessageV1::Shutdown {
            deadline_ms: uint_of("deadline_ms")?,
        },
        "shutdown_ack" => MessageV1::ShutdownAck,
        "reconcile" => MessageV1::Reconcile {
            attempt_id: arr16("attempt_id")?,
            generation_id: arr16("generation_id")?,
        },
        "reconcile_result" => MessageV1::ReconcileResult {
            result: text_of("result")?,
        },
        "error" => MessageV1::Error {
            code: text_of("code")?,
            detail: text_of("detail")?,
        },
        _ => return Err(ProtocolError::UnknownType),
    })
}

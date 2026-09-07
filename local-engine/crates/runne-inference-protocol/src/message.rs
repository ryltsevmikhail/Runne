//! Message catalog V1: exact type spellings and typed bodies
//! (PROTOCOL.md §Message catalog).

/// Typed message. Body fields are the minimum required by the catalog;
/// opaque correlation values travel as byte strings.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageV1 {
    Hello {
        client_nonce: [u8; 16],
        runtime_identity: String,
        adapter_identity: String,
        backend_profile_id: String,
        model_identity: String,
    },
    Welcome {
        host_nonce: [u8; 16],
        session_id: [u8; 16],
        generation: u64,
        host_identity: String,
        backend_profile_id: String,
        max_frame_bytes: u32,
    },
    Ready {
        transcript_digest: [u8; 32],
    },
    LoadModel {
        model_identity: String,
        load_id: [u8; 16],
        artifact_digest: String,
        byte_length: u64,
    },
    GenerationRequest {
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        prepared_request_ref: String,
    },
    GenerationStarted {
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
    },
    StreamItem {
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
        stream_sequence: u64,
        kind: String,
        payload: Vec<u8>,
    },
    StreamAck {
        stream_id: [u8; 16],
        highest_sequence: u64,
    },
    Cancel {
        generation_id: [u8; 16],
        attempt_id: [u8; 16],
        cancel_id: [u8; 16],
    },
    CancelAck {
        cancel_id: [u8; 16],
        disposition: String,
    },
    Health,
    HealthResult {
        state: String,
    },
    Drain {
        deadline_ms: u64,
    },
    DrainAck,
    Shutdown {
        deadline_ms: u64,
    },
    ShutdownAck,
    Reconcile {
        attempt_id: [u8; 16],
        generation_id: [u8; 16],
    },
    ReconcileResult {
        result: String,
    },
    Error {
        code: String,
        detail: String,
    },
}

pub fn type_name(message: &MessageV1) -> &'static str {
    match message {
        MessageV1::Hello { .. } => "hello",
        MessageV1::Welcome { .. } => "welcome",
        MessageV1::Ready { .. } => "ready",
        MessageV1::LoadModel { .. } => "load_model",
        MessageV1::GenerationRequest { .. } => "generation_request",
        MessageV1::GenerationStarted { .. } => "generation_started",
        MessageV1::StreamItem { .. } => "stream_item",
        MessageV1::StreamAck { .. } => "stream_ack",
        MessageV1::Cancel { .. } => "cancel",
        MessageV1::CancelAck { .. } => "cancel_ack",
        MessageV1::Health => "health",
        MessageV1::HealthResult { .. } => "health_result",
        MessageV1::Drain { .. } => "drain",
        MessageV1::DrainAck => "drain_ack",
        MessageV1::Shutdown { .. } => "shutdown",
        MessageV1::ShutdownAck => "shutdown_ack",
        MessageV1::Reconcile { .. } => "reconcile",
        MessageV1::ReconcileResult { .. } => "reconcile_result",
        MessageV1::Error { .. } => "error",
    }
}

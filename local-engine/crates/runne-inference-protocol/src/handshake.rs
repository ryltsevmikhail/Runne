//! Handshake: hello → welcome → ready with HMAC proofs over canonical
//! byte forms (PROTOCOL.md §Handshake), producing paired sessions.

use crate::auth::{Direction, LaunchSecret, SessionKeys, hmac};
use crate::cbor::{self, Cbor};
use crate::error::ProtocolError;
use crate::frame::{self, MAX_CONTROL_FRAME, WIRE_VERSION};
use crate::request::{MessageV1, decode_body, encode_body, type_name};
use crate::stream::Session;

pub struct ClientHelloState {
    pub(crate) canonical_hello: Vec<u8>,
    // Adapter identity fields are consumed by the provider adapter
    // (engine Task 8) to bind the session to the exact request identity.
    #[allow(dead_code)]
    pub(crate) client_nonce: [u8; 16],
    #[allow(dead_code)]
    pub(crate) adapter_identity: String,
    #[allow(dead_code)]
    pub(crate) backend_profile_id: String,
    #[allow(dead_code)]
    pub(crate) model_identity: String,
}

fn hello_map(
    client_nonce: &[u8; 16],
    runtime_identity: &str,
    adapter_identity: &str,
    backend_profile_id: &str,
    model_identity: &str,
) -> Cbor {
    let body = encode_body(&MessageV1::Hello {
        client_nonce: *client_nonce,
        runtime_identity: runtime_identity.to_string(),
        adapter_identity: adapter_identity.to_string(),
        backend_profile_id: backend_profile_id.to_string(),
        model_identity: model_identity.to_string(),
    });
    let mut map = std::collections::BTreeMap::new();
    map.insert(b"v".to_vec(), Cbor::Unsigned(WIRE_VERSION));
    map.insert(b"t".to_vec(), Cbor::Text("hello".into()));
    map.insert(b"client_nonce".to_vec(), Cbor::Bytes(client_nonce.to_vec()));
    let Cbor::Map(body_map) = body else {
        unreachable!()
    };
    for (k, v) in body_map {
        map.insert(k, v);
    }
    Cbor::Map(map)
}

/// Client step 1: build and send an authenticated `hello` (proof included;
/// the frame is technically unMACed pre-key — the proof IS the MAC).
pub fn client_hello(
    secret: &LaunchSecret,
    client_nonce: &[u8; 16],
    runtime_identity: &str,
    adapter_identity: &str,
    backend_profile_id: &str,
    model_identity: &str,
) -> Result<(Vec<u8>, ClientHelloState), ProtocolError> {
    let map = hello_map(
        client_nonce,
        runtime_identity,
        adapter_identity,
        backend_profile_id,
        model_identity,
    );
    let mut canonical = Vec::new();
    cbor::encode(&map, &mut canonical);
    let proof = hmac(secret.as_bytes(), &[&canonical]);
    let core = [
        ("hello".to_string(), map),
        ("client_proof".to_string(), Cbor::Bytes(proof.to_vec())),
    ];
    let mut outer_map = std::collections::BTreeMap::new();
    for (k, v) in core {
        outer_map.insert(k.into_bytes(), v);
    }
    let out = frame::pack_outer(Cbor::Map(outer_map), MAX_CONTROL_FRAME)?;
    Ok((
        out,
        ClientHelloState {
            canonical_hello: canonical,
            client_nonce: *client_nonce,
            adapter_identity: adapter_identity.to_string(),
            backend_profile_id: backend_profile_id.to_string(),
            model_identity: model_identity.to_string(),
        },
    ))
}

/// Host step 2: verify client proof, emit authenticated `welcome`
/// (host_proof = HMAC(secret, canonical_hello || canonical_welcome_without_proof)).
pub fn host_accept(
    secret: &LaunchSecret,
    hello_bytes: &[u8],
    host_nonce: &[u8; 16],
    session_id: &[u8; 16],
    generation: u64,
    host_identity: &str,
    max_frame_bytes: u32,
) -> Result<(Vec<u8>, Session), ProtocolError> {
    let (value, canonical) = frame::decode_frame(hello_bytes, MAX_CONTROL_FRAME)?;
    if !canonical {
        return Err(ProtocolError::NonCanonical);
    }
    let Cbor::Map(map) = &value else {
        return Err(ProtocolError::Malformed);
    };
    let proof = match map.get(b"client_proof".as_slice()) {
        Some(Cbor::Bytes(b)) if b.len() == 32 => {
            let mut p = [0u8; 32];
            p.copy_from_slice(b);
            p
        }
        _ => return Err(ProtocolError::AuthenticationFailed),
    };
    let hello_map_value = match map.get(b"hello".as_slice()) {
        Some(h) => h.clone(),
        None => return Err(ProtocolError::Malformed),
    };
    let mut hello_canonical = Vec::new();
    cbor::encode(&hello_map_value, &mut hello_canonical);
    let expected = hmac(secret.as_bytes(), &[&hello_canonical]);
    if expected != proof {
        return Err(ProtocolError::AuthenticationFailed);
    }
    // Version negotiation: strict major match.
    let Cbor::Map(hm) = &hello_map_value else {
        return Err(ProtocolError::Malformed);
    };
    match hm.get(b"v".as_slice()) {
        Some(Cbor::Unsigned(WIRE_VERSION)) => {}
        _ => return Err(ProtocolError::ProtocolMismatch),
    }

    let mut welcome_body = std::collections::BTreeMap::new();
    welcome_body.insert(b"host_nonce".to_vec(), Cbor::Bytes(host_nonce.to_vec()));
    welcome_body.insert(b"session_id".to_vec(), Cbor::Bytes(session_id.to_vec()));
    welcome_body.insert(b"generation".to_vec(), Cbor::Unsigned(generation));
    welcome_body.insert(b"host_identity".to_vec(), Cbor::Text(host_identity.into()));
    welcome_body.insert(
        b"max_frame_bytes".to_vec(),
        Cbor::Unsigned(max_frame_bytes as u64),
    );
    let welcome_map = {
        let mut m = std::collections::BTreeMap::new();
        m.insert(b"v".to_vec(), Cbor::Unsigned(WIRE_VERSION));
        m.insert(b"t".to_vec(), Cbor::Text("welcome".into()));
        m.insert(b"welcome".to_vec(), Cbor::Map(welcome_body));
        Cbor::Map(m)
    };
    let mut welcome_canonical = Vec::new();
    cbor::encode(&welcome_map, &mut welcome_canonical);
    let host_proof = hmac(secret.as_bytes(), &[&hello_canonical, &welcome_canonical]);

    let mut outer = std::collections::BTreeMap::new();
    outer.insert(b"welcome".to_vec(), welcome_map);
    outer.insert(b"host_proof".to_vec(), Cbor::Bytes(host_proof.to_vec()));
    let out = frame::pack_outer(Cbor::Map(outer), MAX_CONTROL_FRAME)?;

    let keys = SessionKeys::derive(
        secret,
        &hello_canonical,
        &welcome_canonical,
        &crate::auth::ContextMaterial {
            channel: *session_id,
            epoch: generation.to_be_bytes(),
            tag: [0, 0, 0],
        },
        crate::auth::SESSION_PURPOSE.as_bytes(),
    )?;
    let session = Session::new(
        keys,
        *session_id,
        generation,
        Direction::H2c,
        max_frame_bytes,
    );
    Ok((out, session))
}

/// Client step 3: verify host proof, send `ready` (seq 0), return the
/// client-side session.
pub fn client_finalize(
    secret: &LaunchSecret,
    state: ClientHelloState,
    welcome_bytes: &[u8],
) -> Result<(Vec<u8>, Session), ProtocolError> {
    let (value, canonical) = frame::decode_frame(welcome_bytes, MAX_CONTROL_FRAME)?;
    if !canonical {
        return Err(ProtocolError::NonCanonical);
    }
    let Cbor::Map(outer) = &value else {
        return Err(ProtocolError::Malformed);
    };
    let host_proof = match outer.get(b"host_proof".as_slice()) {
        Some(Cbor::Bytes(b)) if b.len() == 32 => {
            let mut p = [0u8; 32];
            p.copy_from_slice(b);
            p
        }
        _ => return Err(ProtocolError::AuthenticationFailed),
    };
    let welcome_map = match outer.get(b"welcome".as_slice()) {
        Some(w) => w.clone(),
        None => return Err(ProtocolError::Malformed),
    };
    let mut welcome_canonical = Vec::new();
    cbor::encode(&welcome_map, &mut welcome_canonical);
    let expected = hmac(
        secret.as_bytes(),
        &[&state.canonical_hello, &welcome_canonical],
    );
    if expected != host_proof {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let Cbor::Map(wm) = &welcome_map else {
        return Err(ProtocolError::Malformed);
    };
    let Cbor::Map(wm) = wm.get(b"welcome".as_slice()).cloned().unwrap_or(Cbor::Null) else {
        return Err(ProtocolError::Malformed);
    };
    let session_id = match wm.get(b"session_id".as_slice()) {
        Some(Cbor::Bytes(b)) if b.len() == 16 => {
            let mut s = [0u8; 16];
            s.copy_from_slice(b);
            s
        }
        _ => return Err(ProtocolError::Malformed),
    };
    let generation = match wm.get(b"generation".as_slice()) {
        Some(Cbor::Unsigned(g)) => *g,
        _ => return Err(ProtocolError::Malformed),
    };
    let max_frame = match wm.get(b"max_frame_bytes".as_slice()) {
        Some(Cbor::Unsigned(f)) => u32::try_from(*f).map_err(|_| ProtocolError::Malformed)?,
        _ => return Err(ProtocolError::Malformed),
    };

    let keys = SessionKeys::derive(
        secret,
        &state.canonical_hello,
        &welcome_canonical,
        &crate::auth::ContextMaterial {
            channel: session_id,
            epoch: generation.to_be_bytes(),
            tag: [0, 0, 0],
        },
        crate::auth::SESSION_PURPOSE.as_bytes(),
    )?;
    let mut session = Session::new(keys, session_id, generation, Direction::C2h, max_frame);
    let transcript = crate::auth::hmac(
        secret.as_bytes(),
        &[&state.canonical_hello, &welcome_canonical],
    );
    let ready = session.encode(&MessageV1::Ready {
        transcript_digest: transcript,
    })?;
    Ok((ready, session))
}

/// Convenience for tests/hosts: decode a handshake-encrypted frame of the
/// given type name (sanity guard).
pub fn expect_type(bytes: &[u8], expected: &str) -> Result<(), ProtocolError> {
    let (_, canonical) = frame::decode_frame(bytes, MAX_CONTROL_FRAME)?;
    if !canonical {
        return Err(ProtocolError::NonCanonical);
    }
    let message = decode_body_bytes(bytes)?;
    if type_name(&message) != expected {
        return Err(ProtocolError::UnknownType);
    }
    Ok(())
}

fn decode_body_bytes(bytes: &[u8]) -> Result<MessageV1, ProtocolError> {
    let (value, _) = frame::decode_frame(bytes, MAX_CONTROL_FRAME)?;
    let Cbor::Map(map) = &value else {
        return Err(ProtocolError::Malformed);
    };
    let t = match map.get(b"t".as_slice()) {
        Some(Cbor::Text(s)) => s.clone(),
        _ => return Err(ProtocolError::Malformed),
    };
    let body = match map.get(b"body".as_slice()) {
        Some(b) => b.clone(),
        None => return Err(ProtocolError::Malformed),
    };
    decode_body(&t, &body)
}

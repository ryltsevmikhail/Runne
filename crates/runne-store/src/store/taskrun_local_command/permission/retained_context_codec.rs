use super::{
    codec,
    retained_context::{
        CaptureContextRowV1, ContextErrorV1, OriginalCaptureContextV1, validate_correlation,
    },
    retained_context_correlation as correlation,
    retained_context_cursor::Cursor,
    retained_context_policy_wire as policy_wire, retained_context_scope_wire as scope_wire,
};
use ContextErrorV1::{CorrelationMismatch, MalformedWire, UnsupportedWireVersion};
use sha2::{Digest, Sha256};
const DOMAIN: &[u8] = b"runne:d21:x2-original-capture-context:v1\0";

pub(crate) fn encode(context: &OriginalCaptureContextV1) -> Result<Vec<u8>, ContextErrorV1> {
    if context.source_policy_version != 2
        || context.command_policy_version != 1
        || context.preset_version != 1
    {
        return Err(UnsupportedWireVersion);
    }
    let mut out = Vec::new();
    out.extend(1u16.to_be_bytes());
    out.push(1);
    out.extend(context.capture_digest);
    out.extend(context.canonical_binding_digest);
    out.extend(context.source_policy_version.to_be_bytes());
    out.extend(context.command_policy_version.to_be_bytes());
    out.extend(context.preset_version.to_be_bytes());
    scope_wire::encode(&context.scope, &mut out)?;
    policy_wire::encode_snapshot(&context.closed_snapshot, &mut out)?;
    if context.approval.expires_at_unix_ms <= 0 {
        return Err(MalformedWire);
    }
    out.extend(context.approval.expires_at_unix_ms.to_be_bytes());
    out.extend(context.approval.relevant_policy_digest.as_bytes());
    policy_wire::encode_projection(context.semantic_projection, &mut out)?;
    // All accepted roots occupy <280768 bytes; remaining fields occupy <512.
    // The 1 MiB wire ceiling cannot narrow the existing checked source domain.
    if out.len() > 1048576 {
        return Err(MalformedWire);
    }
    Ok(out)
}
pub(crate) fn context_digest(bytes: &[u8]) -> Result<[u8; 32], ContextErrorV1> {
    if bytes.is_empty() || bytes.len() > 1048576 {
        return Err(MalformedWire);
    }
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    Ok(hash.finalize().into())
}
pub(crate) fn decode_checked(
    bytes: &[u8],
    digest: &[u8; 32],
    capture_bytes: &[u8],
    capture_digest: &[u8; 32],
    row: &CaptureContextRowV1,
) -> Result<OriginalCaptureContextV1, ContextErrorV1> {
    if context_digest(bytes)? != *digest
        || codec::binding_digest(capture_bytes).map_err(|_| MalformedWire)? != *capture_digest
    {
        return Err(CorrelationMismatch);
    }
    let capture = codec::decode(capture_bytes).map_err(|_| MalformedWire)?;
    let mut cursor = Cursor::new(bytes)?;
    if cursor.u16()? != 1 || cursor.u8()? != 1 {
        return Err(UnsupportedWireVersion);
    }
    let original_digest = cursor.array()?;
    let canonical_binding_digest = cursor.array()?;
    let source_policy_version = cursor.u64()?;
    let command_policy_version = cursor.u64()?;
    let preset_version = cursor.u16()?;
    if source_policy_version != 2 || command_policy_version != 1 || preset_version != 1 {
        return Err(UnsupportedWireVersion);
    }
    let scope_data = scope_wire::decode(&mut cursor)?;
    let closed_snapshot = policy_wire::decode_snapshot(&mut cursor)?;
    let expiry = cursor.i64()?;
    let relevant = cursor.array()?;
    let semantic_projection = policy_wire::decode_projection(
        &mut cursor,
        preset_version,
        source_policy_version,
        command_policy_version,
    )?;
    if !cursor.finished() {
        return Err(MalformedWire);
    }
    let scope = scope_data.reconstruct(&capture, &closed_snapshot)?;
    let (approval, selection, limits) =
        correlation::reconstruct(&capture, &scope, expiry, relevant)?;
    let context = OriginalCaptureContextV1 {
        capture_digest: original_digest,
        canonical_binding_digest,
        source_policy_version,
        command_policy_version,
        preset_version,
        scope,
        closed_snapshot,
        approval,
        selection,
        limits,
        semantic_projection,
    };
    validate_correlation(&context, &capture, capture_digest, row)?;
    if encode(&context)?.as_slice() != bytes {
        return Err(MalformedWire);
    }
    Ok(context)
}

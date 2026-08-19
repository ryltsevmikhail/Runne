// ── CborDecoder ───────────────────────────────────────────────────────────

/// Deterministic CBOR decoder with bounds checking.
pub struct CborDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

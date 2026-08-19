// ── DeterministicCodec trait ──────────────────────────────────────────────

/// Types that can be deterministically encoded/decoded as CBOR.
pub trait DeterministicCodec: Sized {
    /// The registered message type ID for this type.
    const MESSAGE_TYPE_ID: u32;

    /// Encode `self` into the encoder.
    fn encode(&self, enc: &mut CborEncoder) -> Result<(), EncodeError>;

    /// Decode `Self` from the decoder. `type_id` is the wire type ID
    /// and must match `MESSAGE_TYPE_ID`.
    fn decode(type_id: u32, dec: &mut CborDecoder) -> Result<Self, DecodeError>;
}

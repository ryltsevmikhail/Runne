//! Canonical prefix-free bootstrap-v3 transcript encoding.

/// Domain separator for every bootstrap-v3 transcript.
pub const BOOTSTRAP_TRANSCRIPT_DOMAIN: &[u8; 16] = b"RUNNE_BOOTSTRAP\0";
/// Number of canonical length-prefixed fields.
pub const BOOTSTRAP_TRANSCRIPT_FIELD_COUNT: usize = 16;
/// Reserved field replaced by the typed final-proof server nonce.
pub const SERVER_NONCE_FIELD_INDEX: usize = 15;

/// Borrowed bootstrap transcript fields in the normative protocol order.
pub struct BootstrapTranscriptV3<'a> {
    /// Version of the bootstrap HMAC key/byte contract.
    pub key_version: u16,
    /// Ordered fields: `0 protocol`, `1 launch_authority`, `2 principal`,
    /// `3 lineage`, `4 profile`, `5 schema`, `6 executable`, `7 instance`,
    /// `8 generation`, `9 session`, `10 endpoint`, `11 method`,
    /// `12 not_before`, `13 expiry`, `14 client_nonce`, and required-empty
    /// `15 server_nonce` (filled only by [`encode_final_transcript`]).
    pub fields: [&'a [u8]; BOOTSTRAP_TRANSCRIPT_FIELD_COUNT],
}

/// Fail-closed canonical transcript encoding error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapTranscriptError {
    /// One field cannot be represented by the normative `u32be` length.
    FieldTooLong { index: usize },
    /// Callers must not supply server nonce bytes through the borrowed fields.
    NonEmptyServerNonceSlot,
}

/// Encodes the preallocation transcript with a zero-length server nonce slot.
///
/// # Errors
///
/// Rejects a non-empty reserved nonce slot or a field whose length does not
/// fit the normative `u32be` prefix.
pub fn encode_preallocation_transcript(
    input: &BootstrapTranscriptV3<'_>,
) -> Result<Vec<u8>, BootstrapTranscriptError> {
    encode(input, None)
}

/// Encodes the final transcript by replacing only the reserved nonce slot.
///
/// # Errors
///
/// Rejects a non-empty reserved nonce slot or a field whose length does not
/// fit the normative `u32be` prefix.
pub fn encode_final_transcript(
    input: &BootstrapTranscriptV3<'_>,
    server_nonce: [u8; 32],
) -> Result<Vec<u8>, BootstrapTranscriptError> {
    encode(input, Some(&server_nonce))
}

fn encode(
    input: &BootstrapTranscriptV3<'_>,
    server_nonce: Option<&[u8; 32]>,
) -> Result<Vec<u8>, BootstrapTranscriptError> {
    if !input.fields[SERVER_NONCE_FIELD_INDEX].is_empty() {
        return Err(BootstrapTranscriptError::NonEmptyServerNonceSlot);
    }
    let mut output = Vec::new();
    output.extend_from_slice(BOOTSTRAP_TRANSCRIPT_DOMAIN);
    output.extend_from_slice(&input.key_version.to_be_bytes());
    for (index, field) in input.fields[..SERVER_NONCE_FIELD_INDEX].iter().enumerate() {
        append_field(&mut output, index, field)?;
    }
    append_field(
        &mut output,
        SERVER_NONCE_FIELD_INDEX,
        server_nonce.map_or(&[][..], |nonce| &nonce[..]),
    )?;
    Ok(output)
}

fn append_field(
    output: &mut Vec<u8>,
    index: usize,
    field: &[u8],
) -> Result<(), BootstrapTranscriptError> {
    let length =
        u32::try_from(field.len()).map_err(|_| BootstrapTranscriptError::FieldTooLong { index })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

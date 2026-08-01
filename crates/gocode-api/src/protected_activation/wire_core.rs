fn derive_key(secret: &[u8; 32], role: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts fixed keys");
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(role);
    mac.finalize().into_bytes().into()
}

fn authenticated_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts fixed keys");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(&PROTOCOL_SCHEMA_VERSION.to_be_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|character| character.is_control())
}

fn write_key(encoder: &mut CborEncoder, key: u64) {
    encoder.write_unsigned(key);
}

fn expect_key(decoder: &mut CborDecoder<'_>, expected: u64) -> Result<(), DecodeError> {
    let key = decoder.read_unsigned(expected.max(16))?;
    if key == expected {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key })
    }
}

fn expect_message_type(decoder: &mut CborDecoder<'_>, expected: u32) -> Result<(), DecodeError> {
    let actual = decoder.read_unsigned(u64::from(u32::MAX))?;
    if actual == u64::from(expected) {
        Ok(())
    } else {
        Err(DecodeError::UnknownMessageType {
            type_id: u32::try_from(actual).unwrap_or(u32::MAX),
        })
    }
}

fn expect_schema(decoder: &mut CborDecoder<'_>) -> Result<(), DecodeError> {
    expect_key(decoder, 1)?;
    if decoder.read_unsigned(u64::from(u32::MAX))? == u64::from(PROTOCOL_SCHEMA_VERSION) {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key: 1 })
    }
}

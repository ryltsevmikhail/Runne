fn add_representations(representations: &mut Vec<Vec<u8>>, value: &[u8]) {
    representations.push(value.to_vec());
    let standard = base64::engine::general_purpose::STANDARD.encode(value);
    representations.push(standard.as_bytes().to_vec());
    representations.push(standard.trim_end_matches('=').as_bytes().to_vec());
    representations.push(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(value)
            .into_bytes(),
    );
    representations.push(hex::encode(value).into_bytes());
    representations.push(hex::encode_upper(value).into_bytes());
}

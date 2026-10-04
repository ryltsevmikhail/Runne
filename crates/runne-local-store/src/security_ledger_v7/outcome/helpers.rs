fn simple(output: &mut Vec<u8>, tag: u8, id: &BoundedCanonicalId, version_value: u64) -> Result<(), SecurityStateError> {
    output.push(tag);
    codec::put_id(output, id)?;
    valid_version(version_value)?;
    output.extend(version_value.to_be_bytes());
    Ok(())
}

include!("simple_decode.rs");

fn valid_version(value: u64) -> Result<u64, SecurityStateError> {
    (value != 0).then_some(value).ok_or(SecurityStateError::InvalidTransition)
}

fn payload_object(
    value: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, ReplayClientError> {
    value
        .as_object()
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn bounded_string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    maximum_bytes: usize,
) -> Result<&'a str, ReplayClientError> {
    let value = string_field(object, key)?;
    if value.is_empty() || value.len() > maximum_bytes {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(value)
}

fn uuid_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<CanonicalId, ReplayClientError> {
    parse_uuid_v7(string_field(object, key)?)
}

fn optional_uuid_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<CanonicalId>, ReplayClientError> {
    match object.get(key) {
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_str()
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
            .and_then(parse_uuid_v7)
            .map(Some),
        None => Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        )),
    }
}

fn u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn positive_u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ReplayClientError> {
    let value = u64_field(object, key)?;
    if value == 0 {
        return Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ));
    }
    Ok(value)
}

fn u32_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u32, ReplayClientError> {
    u32::try_from(u64_field(object, key)?)
        .map_err(|_| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn i64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<i64, ReplayClientError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))
}

fn enum_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    allowed: &[&str],
) -> Result<(), ReplayClientError> {
    if allowed.contains(&string_field(object, key)?) {
        Ok(())
    } else {
        Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        ))
    }
}

fn unique_u32_array_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<(), ReplayClientError> {
    let values = object
        .get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        let value = value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| ReplayClientError::new(ReplayClientErrorKind::SchemaMismatch))?;
        if !unique.insert(value) {
            return Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            ));
        }
    }
    Ok(())
}

//! Schema-validated OpenCode `Session.Info` values.

use jsonschema::JSONSchema;

/// Error returned when an OpenCode `Session.Info` value is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Stable human-readable validation detail.
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SessionInfo validation error: {}", self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Schema-validated OpenCode `Session.Info` JSON value.
///
/// Values can only be constructed through [`Self::from_json`] or
/// [`Self::from_slice`], which enforce the wire-size limit and the supplied
/// Draft 2020-12 schema.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenCodeSessionInfo(serde_json::Value);

impl OpenCodeSessionInfo {
    /// Maximum serialized wire size of a `Session.Info` value: 64 KiB.
    pub const MAX_WIRE_BYTES: usize = 65_536;

    /// Validates and creates a `Session.Info` value from JSON.
    pub fn from_json(
        value: serde_json::Value,
        schema: &JSONSchema,
    ) -> Result<Self, ValidationError> {
        let serialized = serde_json::to_vec(&value).map_err(|error| ValidationError {
            message: format!("serialization failed: {error}"),
        })?;
        if serialized.len() > Self::MAX_WIRE_BYTES {
            return Err(Self::wire_size_error(serialized.len()));
        }

        Self::validate_schema(value, schema)
    }

    /// Validates and creates a `Session.Info` value from wire JSON bytes.
    ///
    /// The byte limit is checked before JSON parsing so oversized untrusted
    /// payloads cannot cause a JSON allocation or schema validation.
    pub fn from_slice(bytes: &[u8], schema: &JSONSchema) -> Result<Self, ValidationError> {
        if bytes.len() > Self::MAX_WIRE_BYTES {
            return Err(Self::wire_size_error(bytes.len()));
        }
        let value = serde_json::from_slice(bytes).map_err(|error| ValidationError {
            message: format!("invalid JSON: {error}"),
        })?;
        Self::validate_schema(value, schema)
    }

    fn wire_size_error(actual: usize) -> ValidationError {
        ValidationError {
            message: format!(
                "value exceeds max wire size: {actual} > {}",
                Self::MAX_WIRE_BYTES
            ),
        }
    }

    fn validate_schema(
        value: serde_json::Value,
        schema: &JSONSchema,
    ) -> Result<Self, ValidationError> {
        if let Err(errors) = schema.validate(&value) {
            return Err(ValidationError {
                message: errors
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        Ok(Self(value))
    }

    /// Returns the schema-validated JSON value.
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Consumes this wrapper and returns its already-validated JSON value.
    pub fn into_value(self) -> serde_json::Value {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_schema() -> JSONSchema {
        let schema_value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/schemas/session-info-v1.schema.json"
        ))
        .expect("session-info schema is valid JSON");
        JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema_value)
            .expect("session-info schema compiles")
    }

    fn minimal_value() -> serde_json::Value {
        serde_json::json!({
            "id": "session-1",
            "slug": "test",
            "projectID": "project-1",
            "directory": "/tmp",
            "title": "Test",
            "version": "1.0",
            "time": { "created": 1000, "updated": 2000 }
        })
    }

    #[test]
    fn accepts_a_valid_minimal_session_info() {
        let schema = load_schema();
        let info = OpenCodeSessionInfo::from_json(minimal_value(), &schema).expect("valid info");
        assert!(info.as_value().is_object());
        assert_eq!(info, info.clone());
    }

    #[test]
    fn rejects_missing_required_fields() {
        let schema = load_schema();
        let value = serde_json::json!({
            "id": "session-1",
            "slug": "test",
            "projectID": "project-1",
            "directory": "/tmp",
            "title": "Test"
        });
        let error = OpenCodeSessionInfo::from_json(value, &schema).expect_err("must reject");
        assert!(!error.message.is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        let schema = load_schema();
        let mut value = minimal_value();
        value["unknown"] = serde_json::json!(true);
        let error = OpenCodeSessionInfo::from_json(value, &schema).expect_err("must reject");
        assert!(!error.message.is_empty());
    }

    #[test]
    fn rejects_values_larger_than_the_wire_limit_before_schema_validation() {
        let schema = load_schema();
        let mut value = minimal_value();
        value["title"] = serde_json::Value::String("x".repeat(OpenCodeSessionInfo::MAX_WIRE_BYTES));
        let error = OpenCodeSessionInfo::from_json(value, &schema).expect_err("must reject");
        assert!(error.message.starts_with("value exceeds max wire size:"));
    }

    #[test]
    fn rejects_whitespace_padded_wire_bytes_before_json_parsing() {
        let schema = load_schema();
        let mut bytes = serde_json::to_vec(&minimal_value()).expect("value serializes");
        bytes.extend(std::iter::repeat_n(
            b' ',
            OpenCodeSessionInfo::MAX_WIRE_BYTES - bytes.len() + 1,
        ));

        let error = OpenCodeSessionInfo::from_slice(&bytes, &schema).expect_err("must reject");
        assert_eq!(
            error.message,
            format!(
                "value exceeds max wire size: {} > {}",
                bytes.len(),
                OpenCodeSessionInfo::MAX_WIRE_BYTES
            )
        );
    }
}

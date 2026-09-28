use crate::{Connection, SecurityStateError};

#[cfg(all(test, feature = "test-support"))]
#[path = "security_schema_v9_tests.rs"]
mod tests;

pub fn validate_v9_schema(connection: &Connection) -> Result<(), SecurityStateError> {
    crate::security_schema_v8::validate_schema_version(connection, 9)
}

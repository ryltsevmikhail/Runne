/// Closed, non-sensitive diagnosis of schema admission for test support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMatcherDiagnosis {
    /// The database passed the normal existing-schema admission check.
    Accepted,
    /// Admission stopped at a static schema matcher or common gate.
    RejectedAt {
        /// Static matcher number; zero identifies a common admission gate.
        matcher: u8,
        /// Closed failure category without SQL details or row contents.
        failure: SchemaMatcherFailure,
    },
}

/// Closed failure category for [`SchemaMatcherDiagnosis`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMatcherFailure {
    /// The checked predicate returned false.
    ShapeMismatch,
    /// A checked SQL operation returned an error.
    QueryError,
    /// Provider matchers passed but a common schema gate rejected admission.
    CommonAdmissionGate,
}

/// Diagnose admission on a caller-retained connection using normal validators.
///
/// The result contains only a static matcher index and a closed failure kind.
/// It never returns SQL errors, row contents, identifiers, paths, or payloads.
pub fn diagnose_schema_matchers(connection: &Connection) -> SchemaMatcherDiagnosis {
    if classify_existing_connection(connection).is_ok() {
        return SchemaMatcherDiagnosis::Accepted;
    }
    let schema_version = match connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(version) if (49..=63).contains(&version) => version,
        Ok(_) => {
            return rejected(0, SchemaMatcherFailure::CommonAdmissionGate);
        }
        Err(_) => return rejected(0, SchemaMatcherFailure::QueryError),
    };

    let matchers = [62_u8, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49];
    let mut latest_rejection = None;
    for matcher_version in matchers {
        if i64::from(matcher_version) > schema_version {
            continue;
        }
        match matcher_at_version(connection, matcher_version, schema_version) {
            Ok(true) => {
                return latest_rejection
                    .unwrap_or_else(|| rejected(0, SchemaMatcherFailure::CommonAdmissionGate));
            }
            Ok(false) => {
                latest_rejection = Some(rejected(
                    matcher_version,
                    SchemaMatcherFailure::ShapeMismatch,
                ))
            }
            Err(_) => {
                latest_rejection = Some(rejected(matcher_version, SchemaMatcherFailure::QueryError))
            }
        }
    }
    latest_rejection.unwrap_or_else(|| rejected(0, SchemaMatcherFailure::CommonAdmissionGate))
}

fn matcher_at_version(
    connection: &Connection,
    matcher: u8,
    actual_version: i64,
) -> SqliteResult<bool> {
    match matcher {
        62 => v63_matches(connection, actual_version),
        61 => v61_matches(connection, actual_version),
        60 => v60_matches(connection, actual_version),
        59 => v59_matches(connection, actual_version),
        58 => v58_matches(connection, actual_version),
        57 => v57_matches(connection, actual_version),
        56 => v56_matches(connection, actual_version),
        55 => v55_matches(connection, actual_version),
        54 => v54_matches(connection, actual_version),
        53 if actual_version == 53 => v53_matches(connection, actual_version),
        53 => v53_base_matches(connection, actual_version),
        52 if actual_version == 52 => v52_matches(connection, actual_version),
        52 => v52_base_matches(connection, actual_version),
        51 if actual_version == 51 => v51_matches(connection, actual_version),
        51 => v51_base_matches(connection, actual_version),
        50 if actual_version == 50 => v50_matches(connection, actual_version),
        50 => v50_base_matches(connection, actual_version),
        49 => v49_matches(connection, actual_version),
        _ => Ok(false),
    }
}

fn rejected(matcher: u8, failure: SchemaMatcherFailure) -> SchemaMatcherDiagnosis {
    SchemaMatcherDiagnosis::RejectedAt { matcher, failure }
}

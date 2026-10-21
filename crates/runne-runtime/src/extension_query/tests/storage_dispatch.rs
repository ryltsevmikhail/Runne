use super::super::*;
use super::fixtures::*;
use MetadataQueryError::{InvalidSnapshot as Invalid, UnsupportedContract as Unsupported};

const VALID_EXTRA_PACKAGE: &str = r#"{"version":"1.0.0","digest":"1111111111111111111111111111111111111111111111111111111111111111"}"#;

// Break caught: ignoring a well-formed extra MCP package; normalized baseline is unchanged.
#[test]
fn mcp_valid_extra_package_field_rejects() {
    assert!(capture(&json()).is_ok());
    let record = MCP.replacen('{', &format!("{{\"package\":{VALID_EXTRA_PACKAGE},"), 1);
    reject(&json().replace(MCP, &record), Invalid);
}

// Breaks caught: permissive maps, dispatch before full syntax, ignored-depth bypass.
#[test]
fn unsupported_storage_and_query_versions_reject() {
    reject(
        &json().replacen("\"schema_version\":1", "\"schema_version\":2", 1),
        Unsupported,
    );
    let owner = capture(&json()).unwrap();
    let mut r = request();
    r.context.contract_version = 2;
    assert_eq!(owner.query(r).unwrap_err(), Unsupported);
}
#[test]
fn schema_two_non_v1_shape_is_unsupported() {
    for shape in ["null", "42", "[[1]]", "{}", "\"future\""] {
        reject(
            &format!(r#"{{"schema_version":2,"registrations":{shape},"future":[2]}}"#),
            Unsupported,
        );
    }
}
#[test]
fn schema_two_last_is_order_independent() {
    reject(
        r#"{"registrations":[[1]],"future":[2],"schema_version":2}"#,
        Unsupported,
    );
}
#[test]
fn schema_zero_is_unsupported() {
    reject(r#"{"schema_version":0}"#, Unsupported);
}
#[test]
fn duplicate_schema_is_invalid_even_with_unsupported() {
    for pair in ["1,2", "2,1", "2,2", "1,1"] {
        let v: Vec<_> = pair.split(',').collect();
        reject(
            &format!(r#"{{"schema_version":{},"schema_version":{}}}"#, v[0], v[1]),
            Invalid,
        );
    }
}
#[test]
fn missing_wrong_type_schema_is_invalid() {
    reject("{}", Invalid);
    for s in ["\"2\"", "1.0", "-1", "65536", "null", "true", "[]", "{}"] {
        reject(&format!(r#"{{"schema_version":{s}}}"#), Invalid);
    }
}
#[test]
fn trailing_malformed_is_invalid_before_dispatch() {
    for tail in ["x", "{}", "[]", "null", ","] {
        reject(&format!(r#"{{"schema_version":2}}{tail}"#), Invalid);
    }
}
#[test]
fn invalid_ignored_nested_data_is_invalid() {
    for nested in ["[1,]", "{\"a\":}", "[true false]", "[NaN]", "{]", "\"\\q\""] {
        reject(
            &format!(r#"{{"schema_version":2,"ignored":{nested}}}"#),
            Invalid,
        );
    }
}
#[test]
fn ignored_nested_depth_is_universally_bounded() {
    for (n, e) in [(63, Unsupported), (64, Invalid), (1000, Invalid)] {
        reject(
            &format!(
                r#"{{"schema_version":2,"ignored":{}0{}}}"#,
                "[".repeat(n),
                "]".repeat(n)
            ),
            e,
        );
    }
}
#[test]
fn quoted_delimiters_and_escapes_do_not_change_depth() {
    reject(
        r#"{"schema_version":2,"ignored":"{[}\\\"[\\\\]"}"#,
        Unsupported,
    );
    reject(
        r#"{"schema_version":2,"ignored":"\u005b\u007b"}"#,
        Unsupported,
    );
    reject(r#"{"schema_version":2,"ignored":"unterminated\"}"#, Invalid);
}
#[test]
fn v1_second_pass_rejects_header_ignored_keys() {
    reject(&json().replacen('{', "{\"future\":[1],", 1), Invalid);
}
#[test]
fn v1_duplicate_record_kind_and_fields_reject() {
    for (k, v) in [
        ("kind", "\"mcp\""),
        ("id", "\"local-tools\""),
        ("record_revision", "2"),
        ("transport", "\"local_contained\""),
        (
            "required_profile",
            "{\"id\":\"sdk-required\",\"revision\":1}",
        ),
    ] {
        reject(
            &json().replace(MCP, &MCP.replacen('{', &format!("{{\"{k}\":{v},"), 1)),
            Invalid,
        );
    }
    for (k, v) in [
        ("package", "{\"version\":\"1.0.0\",\"digest\":\"00\"}"),
        ("kind", "\"plugin\""),
    ] {
        reject(
            &json().replace(PLUGIN, &PLUGIN.replacen('{', &format!("{{\"{k}\":{v},"), 1)),
            Invalid,
        );
    }
}
#[test]
fn v1_cross_kind_fields_and_unknown_enums_reject() {
    for (original, record) in [
        (
            MCP,
            MCP.replacen('{', &format!("{{\"package\":{VALID_EXTRA_PACKAGE},"), 1),
        ),
        (
            PLUGIN,
            PLUGIN.replacen('{', "{\"transport\":\"local_contained\",", 1),
        ),
        (MCP, MCP.replace("local_contained", "direct")),
        (MCP, MCP.replace("\"mcp\"", "\"other\"")),
    ] {
        reject(&json().replace(original, &record), Invalid);
    }
    // A closed string enum must not admit serde's externally-tagged object spelling.
    for (from, to) in [
        ("\"mcp\"", "{\"mcp\":null}"),
        ("\"plugin\"", "{\"plugin\":null}"),
        ("\"local_contained\"", "{\"local_contained\":null}"),
        ("\"remote_brokered\"", "{\"remote_brokered\":null}"),
    ] {
        reject(&json().replace(from, to), Invalid);
    }
}
#[test]
fn invalid_utf8_precedes_unsupported_dispatch() {
    let mut b = br#"{"schema_version":2,"ignored":""#.to_vec();
    b.push(255);
    b.extend_from_slice(b"\"}");
    assert_eq!(
        ConfiguredExtensionRegistry::capture(file(&b), expected()).unwrap_err(),
        Invalid
    );
}
#[test]
fn unknown_duplicate_fields_and_ids_reject() {
    for (from, to) in [
        (
            "\"principal_id\":",
            "\"principal_id\":\"other\",\"principal_id\":",
        ),
        (
            "\"registration_revision\":",
            "\"registration_revision\":7,\"registration_revision\":",
        ),
        ("\"authority_id\":", "\"unknown\":0,\"authority_id\":"),
        ("\"revision\":1", "\"revision\":1,\"revision\":1"),
        (
            "\"version\":\"1.0.0\"",
            "\"version\":\"1.0.0\",\"version\":\"1.0.0\"",
        ),
        ("\"digest\":", "\"unknown\":0,\"digest\":"),
        (
            "\"id\":\"sdk-required\"",
            "\"id\":\"sdk-required\",\"unknown\":0",
        ),
    ] {
        reject(&json().replace(from, to), Invalid);
    }
    for (key, value) in [
        ("authority_id", format!("\"{AUTH}\"")),
        ("project_id", format!("\"{PROJECT}\"")),
        ("registrations", "[]".into()),
    ] {
        reject(
            &json().replacen('{', &format!("{{\"{key}\":{value},"), 1),
            Invalid,
        );
    }
    reject(
        &json().replace(
            "\"id\":\"sdk-required\"",
            "\"id\":\"sdk-required\",\"id\":\"sdk-required\"",
        ),
        Invalid,
    );
    let digest = "1111111111111111111111111111111111111111111111111111111111111111";
    reject(
        &json().replace(
            &format!("\"digest\":\"{digest}\""),
            &format!("\"digest\":\"{digest}\",\"digest\":\"{digest}\""),
        ),
        Invalid,
    );
    // End-to-end rejection only: baseline digest/count differs. Isolated guard proof is
    // normalization_isolation::duplicate_pair_rejects_before_expectation.
    reject(&document(&format!("{MCP},{MCP}")), Invalid);
}

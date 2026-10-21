use super::super::*;
use super::fixtures::*;
use MetadataQueryError::{InvalidSnapshot as Invalid, UnsupportedContract as Unsupported};
// Break caught: derived visit_seq accidentally admits positional object nodes.
#[test]
fn root_positional_arrays_are_invalid_snapshot() {
    reject("[]", Invalid);
    for v in [0, 1, 2] {
        let fields = [
            v.to_string(),
            format!("\"{AUTH}\""),
            "\"fixture-owner\"".into(),
            format!("\"{PROJECT}\""),
            "7".into(),
            format!(
                "[{PLUGIN},{REMOTE},{},{MCP}]",
                PLUGIN.replace("formatter", "linter")
            ),
        ];
        for n in 1..=6 {
            reject(&format!("[{}]", fields[..n].join(",")), Invalid);
        }
        reject(&format!("[{},0]", fields.join(",")), Invalid);
    }
}
#[test]
fn v1_nested_positional_objects_are_invalid_snapshot() {
    for (original, kind, full) in [
        (
            MCP,
            "mcp",
            "[\"mcp\",\"local-tools\",2,\"local_contained\",{\"id\":\"sdk-required\",\"revision\":1}]",
        ),
        (
            PLUGIN,
            "plugin",
            "[\"plugin\",\"formatter\",3,{\"version\":\"1.0.0\",\"digest\":\"1111111111111111111111111111111111111111111111111111111111111111\"}]",
        ),
    ] {
        for record in ["[]".to_string(), format!("[\"{kind}\"]"), full.to_string()] {
            reject(&json().replace(original, &record), Invalid);
        }
    }
    for arr in ["[]", "[\"sdk-required\"]", "[\"sdk-required\",1]"] {
        reject(
            &json().replace(r#"{"id":"sdk-required","revision":1}"#, arr),
            Invalid,
        );
    }
    for arr in [
        "[]",
        "[\"1.0.0\"]",
        "[\"1.0.0\",\"1111111111111111111111111111111111111111111111111111111111111111\"]",
    ] {
        let old = &PLUGIN[PLUGIN.find("{\"version\"").unwrap()..PLUGIN.len() - 1];
        reject(&json().replace(old, arr), Invalid);
    }
}
#[test]
fn map_controls_preserve_dispatch_and_closed_fields() {
    assert_eq!(
        capture(&json())
            .unwrap()
            .query(request())
            .unwrap()
            .records
            .len(),
        4
    );
    for text in [
        r#"{"schema_version":2,"registrations":[[1]],"future":[2]}"#,
        r#"{"registrations":[[1]],"future":[2],"schema_version":2}"#,
    ] {
        reject(text, Unsupported);
    }
    for text in [
        json().replacen('{', "{\"extra\":0,", 1),
        json().replace(
            "\"record_revision\":2",
            "\"record_revision\":2,\"record_revision\":2",
        ),
        json().replace("\"revision\":1", "\"revision\":1,\"extra\":0"),
        json().replace("\"version\":\"1.0.0\"", "\"version\":\"1.0.0\",\"extra\":0"),
        json().replace(
            "\"schema_version\":1",
            "\"schema_version\":2,\"schema_version\":2",
        ),
    ] {
        reject(&text, Invalid);
    }
}

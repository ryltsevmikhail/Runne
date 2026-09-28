// Unit tests for the CLI output envelope: JSONL render mode contract.

use super::*;

#[test]
fn output_format_parses_jsonl() {
    assert_eq!(OutputFormat::parse("jsonl"), Some(OutputFormat::Jsonl));
    assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
    assert_eq!(OutputFormat::parse("text"), Some(OutputFormat::Text));
    assert_eq!(OutputFormat::parse("yaml"), None);
}

#[test]
fn jsonl_output_renders_one_json_object_per_line() {
    let output = CommandOutput::Jsonl(vec![
        serde_json::json!({ "kind": "submitted", "taskRunId": "t1" }),
        serde_json::json!({ "kind": "terminal", "state": "succeeded" }),
    ]);
    let rendered = render_command_output(&output, OutputFormat::Jsonl);
    let mut lines = rendered.lines();
    let first: serde_json::Value =
        serde_json::from_str(lines.next().expect("first line")).expect("valid json");
    let second: serde_json::Value =
        serde_json::from_str(lines.next().expect("second line")).expect("valid json");
    assert!(
        lines.next().is_none(),
        "exactly two lines, got {rendered:?}"
    );
    assert_eq!(first["kind"], "submitted");
    assert_eq!(second["state"], "succeeded");
    assert!(
        rendered.ends_with('\n'),
        "every JSONL line ends with newline"
    );
}

#[test]
fn jsonl_output_under_json_renders_envelope_with_line_array() {
    let output = CommandOutput::Jsonl(vec![serde_json::json!({ "a": 1 })]);
    let rendered = render_command_output(&output, OutputFormat::Json);
    let value: serde_json::Value = serde_json::from_str(rendered.trim_end()).expect("valid json");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["ok"], true);
    let data = value["data"].as_array().expect("data is a JSON array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["a"], 1);
}

#[test]
fn jsonl_output_under_text_renders_joined_lines() {
    let output = CommandOutput::Jsonl(vec![
        serde_json::json!({ "b": 2 }),
        serde_json::json!({ "c": 3 }),
    ]);
    let rendered = render_command_output(&output, OutputFormat::Text);
    assert_eq!(
        rendered.matches('\n').count(),
        2,
        "two lines plus trailing newline"
    );
    assert!(rendered.contains("\"b\":2") || rendered.contains("\"b\": 2"));
}

#[test]
fn jsonl_error_path_renders_single_error_envelope_on_stderr() {
    let outcome = process_outcome(Err(CliError::Runtime), OutputFormat::Jsonl);
    assert_eq!(outcome.exit_code, 1);
    assert!(outcome.stdout.is_empty());
    let value: serde_json::Value =
        serde_json::from_str(outcome.stderr.trim_end()).expect("valid json error envelope");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "runtime_unavailable");
}

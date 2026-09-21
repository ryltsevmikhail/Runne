//! Control-character handling for terminal failure reasons: text-mode
//! escaping of the Unicode `Cc` category and byte-exact JSON round-trips of
//! raw reasons. Views are built directly — the opaque `TaskRunSnapshot` has
//! no public constructor and terminal reasons are unreachable through the
//! client-facing submit path — so a `Failure`-under-`Failed` pairing here is
//! a view-level fixture, not a wire-validity claim.

use super::*;

fn failed_view(reason: &str) -> TaskRunView {
    TaskRunView {
        task_run_id: "018f2e3a-7000-7000-8000-000000000001".to_owned(),
        state: task_state_name(TaskRunState::Failed),
        stream_version: 3,
        active_attempt_id: None,
        terminal_result: Some(TaskRunTerminalResult::Failure {
            reason: reason.to_owned(),
        }),
    }
}

/// The `terminal result:` line of a get-text block.
fn terminal_line(block: &str) -> &str {
    block
        .lines()
        .find(|line| line.starts_with("terminal result:"))
        .expect("terminal result line")
}

/// Renders one typed payload through the JSON envelope exactly like the CLI
/// process would, then parses the stdout back.
fn json_envelope(data: CommandOutput) -> serde_json::Value {
    let outcome = process_outcome(Ok(data), OutputFormat::Json);
    assert_eq!(outcome.exit_code, 0, "{}", outcome.stderr);
    serde_json::from_str(&outcome.stdout).expect("one-parse JSON envelope")
}

#[test]
fn failure_reason_tab_cr_lf_preserve_row_structure() {
    let reason = "a\tb\nc\rd";
    let row = format_task_list_text(&[failed_view(reason)]);
    assert_eq!(row.lines().count(), 1, "{row}");
    let columns: Vec<&str> = row.split('\t').collect();
    assert_eq!(columns.len(), 5, "{row}");
    assert_eq!(columns[4], "failure: a\\tb\\nc\\rd", "{row}");
    let block = format_task_get_text(&failed_view(reason));
    assert_eq!(block.lines().count(), 5, "{block}");
    assert!(
        block.contains("terminal result: failure: a\\tb\\nc\\rd"),
        "{block}"
    );
}

#[test]
fn ansi_csi_and_osc_sequences_neutralized() {
    for (reason, escaped) in [
        ("\u{1b}[31mred\u{1b}[0m", "\\u{1b}[31mred\\u{1b}[0m"),
        ("\u{1b}]0;title\u{7}", "\\u{1b}]0;title\\u{7}"),
    ] {
        let block = format_task_get_text(&failed_view(reason));
        let line = terminal_line(&block);
        assert!(line.contains(escaped), "{line}");
        assert!(!line.chars().any(char::is_control), "{line}");
    }
}

#[test]
fn nul_bel_del_c1_render_as_unicode_escapes() {
    let block = format_task_get_text(&failed_view("\u{0}\u{7}\u{7f}\u{9b}"));
    let line = terminal_line(&block);
    assert_eq!(line, "terminal result: failure: \\u{0}\\u{7}\\u{7f}\\u{9b}");
    assert!(!line.chars().any(char::is_control), "{line}");
}

#[test]
fn readable_unicode_and_punctuation_pass_through() {
    let reason = "причина №1 — ok ✓ 😀 \"q\" 'a' C:\\path";
    let row = format_task_list_text(&[failed_view(reason)]);
    let columns: Vec<&str> = row.split('\t').collect();
    assert_eq!(columns.len(), 5, "{row}");
    let expected = format!("failure: {reason}");
    assert_eq!(columns[4], expected, "{row}");
}

#[test]
fn json_round_trips_raw_reason() {
    let reason = "a\t\u{1b}[31m\u{7f}причина";
    let view = failed_view(reason);
    let get_envelope = json_envelope(CommandOutput::typed(
        format_task_get_text(&view),
        task_get_json_data(&view),
    ));
    let terminal = &get_envelope["data"]["terminalResult"];
    assert_eq!(terminal["type"], "failure");
    assert_eq!(terminal["reason"].as_str(), Some(reason));

    let list_envelope = json_envelope(CommandOutput::typed(
        format_task_list_text(std::slice::from_ref(&view)),
        task_list_json_data(std::slice::from_ref(&view)),
    ));
    assert_eq!(
        list_envelope["data"]["taskRuns"][0]["terminalResult"]["reason"].as_str(),
        Some(reason)
    );
}

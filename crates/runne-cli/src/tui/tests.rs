use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[test]
fn paste_retains_unicode_and_newlines_without_submission() {
    let mut editor = editor::Editor::default();
    editor.paste("α\r\n日本語\n/new\u{1b}[31m");
    assert_eq!(editor.text(), "α\n日本語\n/new[31m");
    editor.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert_eq!(editor.take(), "α\n日本語\n/new[31");
}

#[test]
fn editor_inserts_at_unicode_cursor_and_alt_enter_is_newline() {
    let mut editor = editor::Editor::default();
    editor.paste("a界");
    editor.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    editor.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
    editor.key(KeyEvent::new(KeyCode::Char('é'), KeyModifiers::NONE));
    assert_eq!(editor.text(), "a\né界");
}

#[test]
fn terminal_sequences_never_reach_rendered_output() {
    let value = render::sanitize("safe\x1b]52;c;secret\x07\x1b[31mred\x1b[0m\r\u{202e}text");
    assert_eq!(value, "saferedtext");
    assert!(!value.chars().any(char::is_control));
}

#[test]
fn tiny_terminal_and_wide_unicode_render_are_bounded() {
    let state = state::State::default();
    for width in [1, 2, 10, 80] {
        for height in [1, 3, 24] {
            let lines = render::lines(&state, width, height);
            assert!(lines.len() <= usize::from(height));
            assert!(
                lines
                    .iter()
                    .all(|line| unicode_width::UnicodeWidthStr::width(line.as_str())
                        <= usize::from(width))
            );
        }
    }
}

#[test]
fn approval_decision_cannot_be_repeated_before_refresh() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.panel = state::Panel::Permissions;
    state.snapshot.approvals.push(ApprovalEntry {
        id: "a".into(),
        ..Default::default()
    });
    let key = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE);
    input::key(&mut state, key, &tx).unwrap();
    input::key(&mut state, key, &tx).unwrap();
    assert_eq!(
        rx.try_recv().unwrap(),
        UiCommand::Approval {
            id: "a".into(),
            decision: true,
            version: 0,
            review_key: String::new()
        }
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn cancel_keeps_active_until_runtime_confirmation() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.snapshot.active = true;
    input::key(
        &mut state,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        &tx,
    )
    .unwrap();
    assert!(state.snapshot.active);
    assert!(state.notice.contains("pending"));
    assert_eq!(rx.try_recv().unwrap(), UiCommand::Cancel);
}

#[test]
fn multiline_cursor_moves_by_unicode_columns() {
    let mut editor = editor::Editor::default();
    editor.paste("界ab\néx");
    editor.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    editor.key(KeyEvent::new(KeyCode::Char('!'), KeyModifiers::NONE));
    assert_eq!(editor.text(), "界!ab\néx");
}

#[test]
fn quit_waits_for_runtime_exit_permission() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    assert!(
        input::key(
            &mut state,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL),
            &tx
        )
        .unwrap()
    );
    assert_eq!(rx.try_recv().unwrap(), UiCommand::Quit);
    assert!(!state.exit_allowed);
    state.event(UiEvent::ExitAllowed);
    assert!(state.exit_allowed);
}

#[test]
fn full_queue_preserves_draft_and_reports_backpressure() {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    tx.try_send(UiCommand::Refresh).unwrap();
    let mut state = state::State::default();
    state.editor.paste("日本語\nkeep draft");
    let result = input::key(
        &mut state,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &tx,
    );
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(state.editor.text(), "日本語\nkeep draft");
}

#[test]
fn completed_gesture_enables_explicit_retry_without_submitting_it() {
    let mut state = state::State::default();
    state
        .submitted_approvals
        .insert(("a".into(), "shown".into()));
    state
        .submitted_approvals
        .insert(("b".into(), "other".into()));
    state.event(UiEvent::ApprovalHandled {
        id: "a".into(),
        review_key: "shown".into(),
    });
    assert!(
        !state
            .submitted_approvals
            .contains(&("a".into(), "shown".into()))
    );
    assert!(
        state
            .submitted_approvals
            .contains(&("b".into(), "other".into()))
    );
}

#[test]
fn eighty_columns_keep_model_status_and_registration_root_visible() {
    let mut state = state::State::default();
    state.snapshot.project = format!("/home/owner/{}/project", "long-directory/".repeat(12));
    state.snapshot.model = "DeepSeek tools".into();
    state.snapshot.status = "Project registration required — use /register".into();
    let lines = render::lines(&state, 80, 24);
    assert!(lines[..3].join(" ").contains("DeepSeek tools"));
    assert!(
        lines[..3]
            .join(" ")
            .contains("Project registration required")
    );
    assert!(lines.join("").contains(&state.snapshot.project));
    assert!(lines.len() <= 24);
    assert!(
        lines
            .iter()
            .all(|line| unicode_width::UnicodeWidthStr::width(line.as_str()) <= 80)
    );
}

#[test]
fn active_session_keeps_new_message_draft_instead_of_sending_it() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.snapshot.active = true;
    state.editor.paste("next message");
    assert!(
        input::key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx
        )
        .is_err()
    );
    assert_eq!(state.editor.text(), "next message");
    assert!(rx.try_recv().is_err());
}
#[test]
fn page_down_scrolls_help_forward_and_page_up_returns() {
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.panel = state::Panel::Help;
    input::key(
        &mut state,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        &tx,
    )
    .unwrap();
    assert_eq!(state.scroll, 5);
    input::key(
        &mut state,
        KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        &tx,
    )
    .unwrap();
    assert_eq!(state.scroll, 0);
}

#[test]
fn login_prompt_hides_typed_key_and_never_puts_it_in_the_editor() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.editor.paste("/login deepseek");
    input::key(
        &mut state,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &tx,
    )
    .unwrap();
    assert!(state.credential_prompt.is_some());
    assert!(state.editor.text().is_empty());
    for character in "sk-secret".chars() {
        input::key(
            &mut state,
            KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
            &tx,
        )
        .unwrap();
    }
    assert_eq!(state.secret.as_str(), "sk-secret");
    assert!(state.editor.text().is_empty());
    assert_eq!(
        render::lines(&state, 80, 24)[22],
        "> [input hidden] · Enter save · Esc cancel"
    );
    assert!(rx.try_recv().is_err());
    input::key(
        &mut state,
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &tx,
    )
    .unwrap();
    assert!(state.credential_prompt.is_none());
    assert!(state.secret.is_empty());
}

#[test]
fn pasted_key_goes_to_the_hidden_buffer_not_the_editor() {
    let mut state = state::State::default();
    state.credential_prompt = Some(crate::ProviderCredentialId::DeepSeek);
    state.push_secret("pasted-secret");
    assert_eq!(state.secret.as_str(), "pasted-secret");
    assert!(state.editor.text().is_empty());
}

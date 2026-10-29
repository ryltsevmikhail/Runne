use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
fn enter() -> KeyEvent {
    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
}
#[test]
fn rejected_submission_restores_original_and_newer_unicode_typing() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.editor.paste("original 世界");
    input::key(&mut state, enter(), &tx).unwrap();
    assert_eq!(
        rx.try_recv().unwrap(),
        UiCommand::Send("original 世界".into())
    );
    state.editor.paste("newer draft");
    assert!(input::key(&mut state, enter(), &tx).is_err());
    assert_eq!(state.editor.text(), "newer draft");
    assert!(rx.try_recv().is_err());
    state.event(UiEvent::Error("root unavailable".into()));
    state.event(UiEvent::SubmissionFinished {
        rejected_draft: Some("original 世界".into()),
    });
    assert_eq!(
        state.editor.text(),
        "original 世界

newer draft"
    );
    assert!(!state.submission_pending);
    assert!(state.notice.contains("root unavailable"));
}
#[test]
fn accepted_or_uncertain_submission_does_not_restore_original_or_erase_new_typing() {
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.editor.paste("already submitted");
    input::key(&mut state, enter(), &tx).unwrap();
    state.editor.paste("next draft");
    state.event(UiEvent::SubmissionFinished {
        rejected_draft: None,
    });
    assert_eq!(state.editor.text(), "next draft");
    assert!(!state.submission_pending);
}
#[test]
fn oversized_combined_restoration_is_retained_but_cannot_resubmit() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut state = state::State::default();
    state.editor.paste(&"b".repeat(40000));
    state.event(UiEvent::SubmissionFinished {
        rejected_draft: Some("a".repeat(40000)),
    });
    assert_eq!(state.editor.text().len(), 80002);
    assert!(input::key(&mut state, enter(), &tx).is_err());
    assert_eq!(state.editor.text().len(), 80002);
    assert!(rx.try_recv().is_err());
}

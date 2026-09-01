use super::is_current_window;

#[test]
fn current_window_is_inclusive_at_issue_and_exclusive_at_expiry() {
    assert!(!is_current_window(10, 20, 9));
    assert!(is_current_window(10, 20, 10));
    assert!(is_current_window(10, 20, 19));
    assert!(!is_current_window(10, 20, 20));
}

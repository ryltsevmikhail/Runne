#[test]
fn relay_ack_requires_exact_relay_to_have_been_taken_once() {
    assert!(!relay_ack_allowed(false, false, Some(&[7; 388]), &[7; 388]));
    assert!(!relay_ack_allowed(true, false, Some(&[7; 388]), &[8; 388]));
    assert!(relay_ack_allowed(true, false, Some(&[7; 388]), &[7; 388]));
    assert!(!relay_ack_allowed(true, true, Some(&[7; 388]), &[7; 388]));
    assert!(!relay_ack_allowed(true, false, None, &[7; 388]));
}

use super::support::{intent, text};

#[test]
fn public_intent_has_a_stable_nonzero_digest() {
    let argv = vec![text("tool"), text("--literal")];
    let first = intent(argv.clone());
    let second = intent(argv);

    assert_ne!(first.digest().as_bytes(), &[0; 32]);
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn changing_a_literal_argv_element_changes_the_digest() {
    assert_ne!(
        intent(vec![text("tool"), text("--literal")]).digest(),
        intent(vec![text("tool"), text("--changed")]).digest(),
    );
}

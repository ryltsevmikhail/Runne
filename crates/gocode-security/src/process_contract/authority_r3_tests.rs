use super::authority_tests::authority;

#[test]
fn prepared_authorization_drop_leaves_state_unchanged() {
    let authority = authority();
    let prepared = authority.prepare_advance().unwrap();

    drop(prepared);

    assert_eq!(authority.state_for_test(), (1, 1, 0));
}

#[test]
fn retaining_authorization_apply_is_idempotent_and_commit_stays_compatible() {
    let authority = authority();
    let mut prepared = authority.prepare_advance().unwrap();

    prepared.apply_retaining_lock();
    prepared.apply_retaining_lock();
    drop(prepared);
    assert_eq!(authority.state_for_test(), (2, 2, 0));
    authority.prepare_advance().unwrap().commit().unwrap();

    assert_eq!(authority.state_for_test(), (3, 3, 0));
}

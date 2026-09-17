#[test]
fn saved_owner_acl_single_any_authorization_is_the_default_form() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    repurpose_empty_owner_acl(&exact.creation_access, unsafe {
        kSecACLAuthorizationAny
    });
    // macOS 27 stores the no-applications owner record with a single `Any`
    // authorization; verification must treat it as the Default owner form.
    assert_eq!(
        verify_decrypt_access(&exact.creation_access),
        Ok(exact.trusted_digest),
    );
}

#[test]
fn owner_acl_with_any_plus_another_authorization_is_rejected() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    repurpose_empty_owner_acl_with_authorizations(
        &exact.creation_access,
        &[unsafe { kSecACLAuthorizationAny }, unsafe {
            kSecACLAuthorizationChangeOwner
        }],
    );
    assert_eq!(
        verify_decrypt_access(&exact.creation_access),
        Err(KeychainAclError::AccessDenied),
    );
}

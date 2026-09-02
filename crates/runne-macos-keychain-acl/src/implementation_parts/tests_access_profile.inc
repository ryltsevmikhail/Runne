fn decrypt_acl_list(access: &SecAccess) -> CFArray<CFType> {
    let acl_list = unsafe {
        SecAccessCopyMatchingACLList(
            access.as_concrete_TypeRef(),
            kSecACLAuthorizationDecrypt.cast(),
        )
    };
    assert!(!acl_list.is_null());
    unsafe { CFArray::wrap_under_create_rule(acl_list) }
}

fn copy_acl_applications(acl: &CFType) -> CFArray<CFType> {
    copy_acl_contents_with(|applications, description, prompt_selector| unsafe {
        SecACLCopyContents(
            acl.as_CFTypeRef(),
            applications,
            description,
            prompt_selector,
        )
    })
    .unwrap()
    .0
}

fn set_access_prompt_selector(access: &SecAccess, prompt_selector: u16) {
    let acl_list = decrypt_acl_list(access);
    for acl in acl_list.iter() {
        let mut applications = ptr::null();
        let mut description = ptr::null();
        let mut existing_prompt_selector = 0;
        let copy_status = unsafe {
            SecACLCopyContents(
                acl.as_CFTypeRef(),
                &raw mut applications,
                &raw mut description,
                &raw mut existing_prompt_selector,
            )
        };
        let applications_owner = RetainedCfOutput::new(applications);
        let description_owner = RetainedCfOutput::new(description);
        status(copy_status).unwrap();
        assert!(!applications.is_null());
        assert!(!description.is_null());
        applications_owner.disarm();
        description_owner.disarm();
        let applications = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
        let description = unsafe { CFString::wrap_under_create_rule(description) };
        status(unsafe {
            SecACLSetContents(
                acl.as_CFTypeRef(),
                applications.as_concrete_TypeRef(),
                description.as_concrete_TypeRef(),
                prompt_selector,
            )
        })
        .unwrap();
    }
}

#[test]
fn every_nonzero_prompt_selector_is_rejected() {
    assert!(prompt_selector_is_unconditional(0));
    for prompt_selector in [1, 2, 4, 8, u16::MAX] {
        assert!(!prompt_selector_is_unconditional(prompt_selector));
    }
}

#[test]
fn repeated_native_prompt_acl_rejection_releases_copied_applications() {
    let current = std::env::current_exe().unwrap();
    let application = trusted_application(&current).unwrap();
    let access = create_exact_application_access(&application, &application).unwrap();
    set_access_prompt_selector(&access, 1);
    let acl_list = decrypt_acl_list(&access);
    let applications = copy_acl_applications(&acl_list.get(0).unwrap());
    let before = applications.retain_count();
    LIVE_COPIED_APPLICATION_LISTS.store(0, Ordering::Relaxed);

    for _ in 0..256 {
        assert_eq!(
            verify_decrypt_access(&access),
            Err(KeychainAclError::AccessDenied)
        );
    }

    assert_eq!(applications.retain_count(), before);
    assert_eq!(LIVE_COPIED_APPLICATION_LISTS.load(Ordering::Relaxed), 0);
}

#[test]
fn noncaller_owned_access_supports_exact_direct_acl_readback() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    assert_eq!(
        verify_decrypt_access(&exact.creation_access).unwrap(),
        exact.trusted_digest
    );
    assert_eq!(
        writer_access_digest(&exact.creation_access),
        Ok(exact.writer_digest)
    );
    assert!(change_acl_is_owner_only(&exact.creation_access).unwrap());
    assert!(verify_noncaller_owner(&exact.creation_access).unwrap());
}

#[test]
fn noncaller_owned_access_has_the_complete_exact_profile() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();

    assert_eq!(
        verify_access_profile(&exact.creation_access, exact.digest),
        Ok(())
    );
    assert!(verify_noncaller_owner(&exact.creation_access).unwrap());
}

#[test]
fn cf_acl_list_owner_clone_loses_matching_authorizations() {
    let current = std::env::current_exe().unwrap();
    let application = trusted_application(&current).unwrap();
    let source = create_exact_application_access(&application, &application).unwrap();
    let cloned = clone_acl_data_with_owner_using_cf_list(&source, 0, 0).unwrap();
    assert!(verify_noncaller_owner(&cloned).unwrap());

    let mut all_acls = ptr::null();
    assert_eq!(
        unsafe { SecAccessCopyACLList(cloned.as_concrete_TypeRef(), &raw mut all_acls) },
        errSecSuccess,
    );
    assert!(!all_acls.is_null());
    let all_acls = unsafe { CFArray::<CFType>::wrap_under_create_rule(all_acls) };
    assert!(!all_acls.is_empty());
    assert!(unsafe {
        SecAccessCopyMatchingACLList(
            cloned.as_concrete_TypeRef(),
            kSecACLAuthorizationDecrypt.cast(),
        )
    }
    .is_null());
}

#[test]
fn change_owner_application_acl_is_rejected() {
    let current = std::env::current_exe().unwrap();
    let application = trusted_application(&current).unwrap();
    let access = create_exact_application_access(&application, &application).unwrap();
    let applications = CFArray::from_CFTypes(&[application]);
    create_application_acl(
        &access,
        &applications,
        unsafe { kSecACLAuthorizationChangeOwner },
    )
    .unwrap();

    assert!(!change_acl_is_owner_only(&access).unwrap());
}

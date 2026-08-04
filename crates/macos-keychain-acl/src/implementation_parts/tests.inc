mod tests {
    use super::*;

    struct TestItem(SecKeychainItem);

    impl Drop for TestItem {
        fn drop(&mut self) {
            let _ = delete_item(&self.0);
        }
    }

    fn item_access(item: &SecKeychainItem) -> SecAccess {
        let mut access = ptr::null_mut();
        // SAFETY: item is live and access is a valid retained out-pointer.
        let access_status =
            unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) };
        let access_owner = RetainedCfOutput::new(access);
        status(access_status).unwrap();
        assert!(!access.is_null());
        access_owner.disarm();
        // SAFETY: the copy call returned a retained access reference.
        unsafe { SecAccess::wrap_under_create_rule(access) }
    }

    fn decrypt_acl_list(access: &SecAccess) -> CFArray<CFType> {
        // SAFETY: access and the static authorization tag are live.
        let acl_list = unsafe {
            SecAccessCopyMatchingACLList(
                access.as_concrete_TypeRef(),
                kSecACLAuthorizationDecrypt.cast(),
            )
        };
        assert!(!acl_list.is_null());
        // SAFETY: the Copy call returned a retained array.
        unsafe { CFArray::wrap_under_create_rule(acl_list) }
    }

    fn copy_acl_applications(acl: &CFType) -> CFArray<CFType> {
        copy_acl_contents_with(|applications, description, prompt_selector| {
            // SAFETY: acl and all retained out-pointers are valid.
            unsafe {
                SecACLCopyContents(
                    acl.as_CFTypeRef(),
                    applications,
                    description,
                    prompt_selector,
                )
            }
        })
        .unwrap()
        .0
    }

    fn set_item_prompt_selector(item: &SecKeychainItem, prompt_selector: u16) {
        let access = item_access(item);
        let acl_list = decrypt_acl_list(&access);
        for acl in acl_list.iter() {
            let mut applications = ptr::null();
            let mut description = ptr::null();
            let mut existing_prompt_selector = 0;
            // SAFETY: acl and retained output pointers are valid.
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
            // SAFETY: both copy outputs are retained and wrapped immediately.
            let applications = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
            let description = unsafe { CFString::wrap_under_create_rule(description) };
            // SAFETY: acl and wrapped contents stay live through the mutation.
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
        // SAFETY: item and access are live for the native update.
        status(unsafe {
            SecKeychainItemSetAccess(item.as_concrete_TypeRef(), access.as_concrete_TypeRef())
        })
        .unwrap();
    }

    #[test]
    fn every_nonzero_prompt_selector_is_rejected() {
        assert!(prompt_selector_is_unconditional(0));
        for prompt_selector in [1, 2, 4, 8, u16::MAX] {
            assert!(!prompt_selector_is_unconditional(prompt_selector));
        }
    }

    #[test]
    fn acl_copy_error_releases_both_retained_outputs() {
        let element = CFString::new("retained application fixture");
        let applications = CFArray::from_CFTypes(&[element]);
        let description =
            CFString::new("retained description fixture long enough to avoid tagged storage");
        let applications_before = applications.retain_count();
        let description_before = description.retain_count();

        for _ in 0..64 {
            let result = copy_acl_contents_with(|applications_out, description_out, prompt| {
                // SAFETY: each fake Copy output receives its own +1 retain and
                // all output pointers are valid for this call.
                unsafe {
                    *applications_out =
                        core_foundation::base::CFRetain(applications.as_CFTypeRef()).cast();
                    *description_out =
                        core_foundation::base::CFRetain(description.as_CFTypeRef()).cast();
                    *prompt = 0;
                }
                -50
            });
            assert_eq!(result.err(), Some(KeychainAclError::OperationFailed));
        }

        let applications_after = applications.retain_count();
        let description_after = description.retain_count();
        for _ in applications_before..applications_after {
            // SAFETY: the RED implementation leaked one fake +1 retain per
            // iteration; release it so a failing regression does not leak.
            unsafe { core_foundation::base::CFRelease(applications.as_CFTypeRef()) };
        }
        for _ in description_before..description_after {
            // SAFETY: same cleanup for the fake retained description output.
            unsafe { core_foundation::base::CFRelease(description.as_CFTypeRef()) };
        }
        assert_eq!(applications_after, applications_before);
        assert_eq!(description_after, description_before);
    }

    #[test]
    fn metadata_copy_error_frees_populated_content_exactly_once() {
        let free_calls = std::cell::Cell::new(0);

        for _ in 0..64 {
            let allocation = std::cell::Cell::new(ptr::null_mut::<u8>());
            let result = copy_nonsecret_metadata_with(
                |metadata_list| {
                    let mut bytes = b"metadata".to_vec().into_boxed_slice();
                    let data = bytes.as_mut_ptr();
                    std::mem::forget(bytes);
                    allocation.set(data);
                    // SAFETY: the list points to the helper's live attribute.
                    unsafe {
                        let attribute = &mut *(*metadata_list).attr;
                        attribute.length = 8;
                        attribute.data = data.cast();
                    }
                    -50
                },
                |metadata_list| {
                    free_calls.set(free_calls.get() + 1);
                    // SAFETY: the fake Copy call allocated exactly the recorded
                    // eight-byte boxed slice and populated this attribute.
                    unsafe {
                        let attribute = &mut *(*metadata_list).attr;
                        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                            attribute.data.cast::<u8>(),
                            attribute.length as usize,
                        )));
                        attribute.data = ptr::null_mut();
                        attribute.length = 0;
                    }
                    allocation.set(ptr::null_mut());
                    errSecSuccess
                },
            );
            if !allocation.get().is_null() {
                // SAFETY: RED cleanup for the fake allocation when the missing
                // guard failed to invoke `free_content`.
                unsafe {
                    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                        allocation.get(),
                        8,
                    )));
                }
            }
            assert_eq!(result, Err(KeychainAclError::OperationFailed));
        }

        assert_eq!(free_calls.get(), 64);
    }

    #[test]
    fn repeated_native_prompt_acl_rejection_releases_copied_applications() {
        let _interaction = SecKeychain::disable_user_interaction().unwrap();
        let keychain = SecKeychain::default().unwrap();
        let current = std::env::current_exe().unwrap();
        let exact = ExactKeychainAccess::new(&current, &current).unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let item = TestItem(
            create_empty_generic_password(
                &keychain,
                &format!("dev.gocode.prompt-ownership-test.{unique}"),
                &format!("prompt-ownership-{unique}"),
                b"non-secret-test-metadata",
                &exact,
            )
            .unwrap(),
        );
        set_item_prompt_selector(&item.0, 1);
        let access = item_access(&item.0);
        let acl_list = decrypt_acl_list(&access);
        let applications = copy_acl_applications(&acl_list.get(0).unwrap());
        let before = applications.retain_count();
        LIVE_COPIED_APPLICATION_LISTS.store(0, Ordering::Relaxed);

        for _ in 0..256 {
            assert_eq!(
                verify_item_access(&item.0, exact.digest()),
                Err(KeychainAclError::AccessDenied)
            );
        }

        assert_eq!(applications.retain_count(), before);
        assert_eq!(LIVE_COPIED_APPLICATION_LISTS.load(Ordering::Relaxed), 0);
    }
}

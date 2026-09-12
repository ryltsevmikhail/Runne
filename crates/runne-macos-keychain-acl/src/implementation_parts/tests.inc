mod tests {
    use super::*;

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
    fn provider_credential_process_lock_is_reentrant_within_a_process() {
        let outer = ProviderCredentialProcessLock::acquire().expect("outer acquire must succeed");
        let inner =
            ProviderCredentialProcessLock::acquire().expect("nested acquire must not self-deadlock");

        let state = PROVIDER_CREDENTIAL_LOCK_STATE.lock().expect("registry must not be poisoned");
        assert_eq!(state.depth, 2, "nested acquire must register a second depth token");
        assert!(state.descriptor.is_some(), "kernel descriptor must stay registered");
        drop(state);

        // Dropping the outer token while the inner one is still held must not
        // release the kernel lock.
        drop(outer);
        let state = PROVIDER_CREDENTIAL_LOCK_STATE.lock().expect("registry must not be poisoned");
        assert_eq!(state.depth, 1, "dropping the outer token must keep the inner token");
        assert!(
            state.descriptor.is_some(),
            "dropping the outer token must not close the registered descriptor"
        );
        drop(state);

        // The final drop closes the descriptor; a fresh acquire only returns
        // if the kernel `flock(LOCK_EX)` was actually released, because a new
        // descriptor would otherwise block against the leaked one forever.
        drop(inner);
        let state = PROVIDER_CREDENTIAL_LOCK_STATE.lock().expect("registry must not be poisoned");
        assert_eq!(state.depth, 0, "dropping the last token must clear the depth");
        assert!(
            state.descriptor.is_none(),
            "dropping the last token must close the registered descriptor"
        );
        drop(state);

        let reacquired =
            ProviderCredentialProcessLock::acquire().expect("re-acquire after release must succeed");
        drop(reacquired);
        let state = PROVIDER_CREDENTIAL_LOCK_STATE.lock().expect("registry must not be poisoned");
        assert_eq!(state.depth, 0, "re-acquired token must drop cleanly");
        assert!(state.descriptor.is_none(), "re-acquired token must release the descriptor");
        drop(state);
    }

    include!("tests_access_profile.inc");
    include!("tests_opaque_profile.inc");
}

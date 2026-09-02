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

    include!("tests_access_profile.inc");
    include!("tests_opaque_profile.inc");
}

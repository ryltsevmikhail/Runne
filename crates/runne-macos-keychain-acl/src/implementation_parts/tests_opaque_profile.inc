fn opaque_acl_records(access: &SecAccess) -> Vec<CFType> {
    let mut list = ptr::null();
    assert_eq!(
        unsafe { SecAccessCopyACLList(access.as_concrete_TypeRef(), &raw mut list) },
        errSecSuccess
    );
    assert!(!list.is_null());
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    list.iter()
        .filter_map(|acl| {
            let mut applications = ptr::null();
            let mut description = ptr::null();
            let mut prompt_selector = 0;
            let status = unsafe {
                SecACLCopyContents(
                    acl.as_CFTypeRef(),
                    &raw mut applications,
                    &raw mut description,
                    &raw mut prompt_selector,
                )
            };
            let _applications = RetainedCfOutput::new(applications);
            let _description = RetainedCfOutput::new(description);
            match status {
                0 => None,
                -25_240 => Some(unsafe { CFType::wrap_under_get_rule(acl.as_CFTypeRef()) }),
                status => panic!("unexpected ACL contents status {status}"),
            }
        })
        .collect()
}

fn opaque_authorizations(acl: &CFType) -> CFArray<CFType> {
    let authorizations = unsafe { SecACLCopyAuthorizations(acl.as_CFTypeRef()) };
    assert!(!authorizations.is_null());
    unsafe { CFArray::wrap_under_create_rule(authorizations) }
}

fn matching_opaque_shape(access: &SecAccess, authorization: CFStringRef) -> (usize, usize) {
    let list = unsafe {
        SecAccessCopyMatchingACLList(access.as_concrete_TypeRef(), authorization.cast())
    };
    assert!(!list.is_null());
    let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
    let change_acl = unsafe { CFString::wrap_under_get_rule(kSecACLAuthorizationChangeACL) };
    let mut empty = 0;
    let mut matching_change_acl = 0;
    for acl in list.iter() {
        let mut applications = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0;
        let status = unsafe {
            SecACLCopyContents(
                acl.as_CFTypeRef(),
                &raw mut applications,
                &raw mut description,
                &raw mut prompt_selector,
            )
        };
        let _applications = RetainedCfOutput::new(applications);
        let _description = RetainedCfOutput::new(description);
        if status != -25_240 {
            continue;
        }
        let authorizations = opaque_authorizations(&acl);
        if authorizations.is_empty() {
            empty += 1;
        } else if authorizations.len() == 1
            && authorizations
                .get(0)
                .is_some_and(|value| *value == change_acl.as_CFType())
        {
            matching_change_acl += 1;
        } else {
            panic!("unexpected opaque authorization shape");
        }
    }
    (empty, matching_change_acl)
}

fn repurpose_empty_owner_acl(access: &SecAccess, authorization: CFStringRef) {
    repurpose_empty_owner_acl_with_authorizations(access, &[authorization]);
}

fn repurpose_empty_owner_acl_with_authorizations(
    access: &SecAccess,
    authorizations: &[CFStringRef],
) {
    let mut empty = opaque_acl_records(access)
        .into_iter()
        .filter(|acl| opaque_authorizations(acl).is_empty());
    let acl = empty.next().expect("one empty owner ACL");
    assert!(empty.next().is_none());
    let authorizations = CFArray::from_CFTypes(
        &authorizations
            .iter()
            .map(|authorization| unsafe { CFString::wrap_under_get_rule(*authorization) })
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        unsafe {
            SecACLUpdateAuthorizations(
                acl.as_CFTypeRef(),
                authorizations.as_concrete_TypeRef(),
            )
        },
        errSecSuccess
    );
    assert_eq!(opaque_acl_records(access).len(), 2);
}

fn target_attached_access() -> (SecAccess, [u8; 32], [u8; 32], Vec<String>) {
    let current = std::env::current_exe().unwrap();
    let application = trusted_application(&current).unwrap();
    let trusted_digest = trusted_application_set_digest(&[&application, &application]).unwrap();
    let writer_digest = trusted_application_set_digest(&[&application]).unwrap();
    let partition_ids = exact_code_partition_ids(&current, &current).unwrap();
    let access =
        create_exact_noncaller_access(&application, &application, &partition_ids).unwrap();
    (access, trusted_digest, writer_digest, partition_ids)
}

#[test]
fn target_attached_profile_components_are_directly_readable() {
    let (access, trusted_digest, writer_digest, partition_ids) = target_attached_access();
    assert_eq!(verify_root_owner_acl_shape(&access), Ok(()));
    assert_eq!(verify_decrypt_access(&access), Ok(trusted_digest));
    assert_eq!(verify_read_access(&access), Ok(trusted_digest));
    for authorization in unsafe {
        [
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        assert_eq!(
            application_acl_digest_with_owner(&access, authorization),
            Ok(writer_digest)
        );
    }
    assert_eq!(copy_partition_ids(&access), Ok(partition_ids));
    assert_eq!(change_acl_is_owner_only(&access), Ok(true));
}

#[test]
fn root_owner_records_have_the_exact_native_authorization_shape() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    let records = opaque_acl_records(&exact.creation_access);
    assert_eq!(records.len(), 2);
    let change_acl = unsafe { CFString::wrap_under_get_rule(kSecACLAuthorizationChangeACL) };
    let mut empty = 0;
    let mut matching = 0;
    for record in records {
        let authorizations = opaque_authorizations(&record);
        if authorizations.is_empty() {
            empty += 1;
        } else if authorizations.len() == 1
            && authorizations
                .get(0)
                .is_some_and(|value| *value == change_acl.as_CFType())
        {
            matching += 1;
        }
    }
    assert_eq!((empty, matching), (1, 1));
    for authorization in unsafe {
        [
            kSecACLAuthorizationAny,
            kSecACLAuthorizationChangeOwner,
            kSecACLAuthorizationDecrypt,
            kSecACLAuthorizationKeychainItemRead,
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
            kSecACLAuthorizationPartitionID,
        ]
    } {
        assert_eq!(matching_opaque_shape(&exact.creation_access, authorization), (1, 0));
    }
    assert_eq!(
        matching_opaque_shape(&exact.creation_access, unsafe {
            kSecACLAuthorizationChangeACL
        }),
        (1, 1)
    );
}

#[test]
fn decrypt_rejects_an_unexpected_opaque_acl() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    repurpose_empty_owner_acl(&exact.creation_access, unsafe {
        kSecACLAuthorizationDecrypt
    });
    assert_eq!(
        verify_decrypt_access(&exact.creation_access),
        Err(KeychainAclError::AccessDenied)
    );
}

#[test]
fn read_rejects_an_unexpected_opaque_acl() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    repurpose_empty_owner_acl(&exact.creation_access, unsafe {
        kSecACLAuthorizationKeychainItemRead
    });
    assert_eq!(
        verify_read_access(&exact.creation_access),
        Err(KeychainAclError::AccessDenied)
    );
}

#[test]
fn every_writer_operation_rejects_an_unexpected_opaque_acl() {
    let current = std::env::current_exe().unwrap();
    for authorization in unsafe {
        [
            kSecACLAuthorizationEncrypt,
            kSecACLAuthorizationDelete,
            kSecACLAuthorizationKeychainItemModify,
            kSecACLAuthorizationKeychainItemDelete,
        ]
    } {
        let exact = ExactKeychainAccess::new(&current, &current).unwrap();
        repurpose_empty_owner_acl(&exact.creation_access, authorization);
        assert_eq!(
            application_acl_digest_with_owner(&exact.creation_access, authorization),
            Err(KeychainAclError::AccessDenied)
        );
    }
}

#[test]
fn partition_rejects_an_unexpected_opaque_acl() {
    let current = std::env::current_exe().unwrap();
    let exact = ExactKeychainAccess::new(&current, &current).unwrap();
    repurpose_empty_owner_acl(&exact.creation_access, unsafe {
        kSecACLAuthorizationPartitionID
    });
    assert_eq!(
        copy_partition_ids(&exact.creation_access),
        Err(KeychainAclError::AccessDenied)
    );
}

#[test]
fn partition_readback_requires_homogeneous_records() {
    let full = vec![
        String::from("cdhash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        String::from("cdhash:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    ];
    let duplicate = full.clone();
    let subset = vec![String::from("cdhash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")];
    let mut foreign = full.clone();
    foreign.push(String::from("cdhash:cccccccccccccccccccccccccccccccccccccccc"));

    // macOS 27 duplicates the full record next to subset records, and
    // decrypt enforcement requires the reader in every record, so the
    // readback is homogeneous: duplicates of the full record pass, while
    // a subset record, any foreign id, or no record at all is rejected.
    assert_eq!(
        homogeneous_partition_ids(&[full.clone(), duplicate]),
        Ok(full.clone())
    );
    assert_eq!(
        homogeneous_partition_ids(&[full.clone(), subset]),
        Err(KeychainAclError::AccessDenied)
    );
    assert_eq!(
        homogeneous_partition_ids(&[full, foreign]),
        Err(KeychainAclError::AccessDenied)
    );
    assert_eq!(
        homogeneous_partition_ids(&[]),
        Err(KeychainAclError::AccessDenied)
    );
    assert_eq!(
        homogeneous_partition_ids(&[Vec::new()]),
        Err(KeychainAclError::AccessDenied)
    );
}

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

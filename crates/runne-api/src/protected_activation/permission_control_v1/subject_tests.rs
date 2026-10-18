use super::*;

#[test]
fn stable_subject_digest_matches_the_fixed_domain_vector() {
    let principal = crate::ApiPrincipalId::new("local-owner").unwrap();
    assert_eq!(
        permission_control_stable_subject_digest_v1(&principal).unwrap(),
        [
            0x71, 0xf6, 0x33, 0xc7, 0x7c, 0x77, 0xd8, 0x62, 0xaf, 0x06, 0x37, 0x09, 0xa9, 0x9c,
            0x95, 0x97, 0x0a, 0x2a, 0x02, 0x8b, 0xea, 0x5c, 0xfc, 0xa5, 0xe9, 0x61, 0x4d, 0xc4,
            0x3d, 0x7c, 0x7a, 0xb9,
        ]
    );
}

#[test]
fn stable_subject_preserves_exact_principal_bytes_and_rejects_unicode_controls() {
    let canonical = crate::ApiPrincipalId::new("local-owner").unwrap();
    let case_changed = crate::ApiPrincipalId::new("Local-owner").unwrap();
    assert_ne!(
        permission_control_stable_subject_digest_v1(&canonical).unwrap(),
        permission_control_stable_subject_digest_v1(&case_changed).unwrap()
    );

    let control = crate::ApiPrincipalId::new("user\u{0085}").unwrap();
    assert_eq!(
        permission_control_stable_subject_digest_v1(&control),
        Err(PermissionControlSubjectErrorV1::InvalidPrincipal)
    );
}

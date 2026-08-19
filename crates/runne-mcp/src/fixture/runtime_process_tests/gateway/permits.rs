use super::super::super::process_call::{process_permit_digest, process_permit_id};

#[test]
fn permit_is_full_lowercase_digest() {
    let permit = process_permit_id(process_permit_digest([1; 32], &[2; 16], [3; 32]));
    assert_eq!(permit.len(), 64);
    assert!(
        permit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn permit_changes_with_capability_material() {
    assert_ne!(
        process_permit_id(process_permit_digest([1; 32], &[2; 16], [3; 32])),
        process_permit_id(process_permit_digest([1; 32], &[4; 16], [3; 32])),
    );
}

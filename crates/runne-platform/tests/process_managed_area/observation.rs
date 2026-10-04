use super::*;

#[test]
fn exact_area_absence_observation_is_read_only_and_fails_closed() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(71);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: exact_area_absence_observation_is_read_only_and_fails_closed");
    let identity = area.identity().clone();
    assert_eq!(root.area_is_absent(&identity), Ok(false));
    assert!(root.reopen_area(identity.clone(), bind).is_ok());

    for offset in [4usize, 20, 28, 36, 44] {
        let mut bytes = identity.to_bytes();
        bytes[offset] ^= 1;
        let changed = ManagedAreaIdentity::from_bytes(&bytes).expect("valid identity fields");
        assert_eq!(
            root.area_is_absent(&changed),
            Err(ManagedAreaError::Unverified)
        );
    }

    area.remove_empty();
    assert_eq!(root.area_is_absent(&identity), Ok(true));

    let replacement = root.create_area(bind).expect("recreate exact bound name");
    let replacement_identity = replacement.identity().clone();
    assert_eq!(
        root.area_is_absent(&identity),
        Err(ManagedAreaError::Unverified)
    );
    assert_eq!(root.area_is_absent(&replacement_identity), Ok(false));
    replacement.remove_empty().expect("remove replacement");
    assert_eq!(root.area_is_absent(&replacement_identity), Ok(true));
}

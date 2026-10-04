use super::{ManagedAreaError, area_or_skip, binding, root_or_skip};

#[test]
fn durable_terminal_cleanup_removes_only_exact_empty_area_and_is_idempotent() {
    let Some(root) = root_or_skip() else { return };
    let bind = binding(93);
    let Some(area) = area_or_skip(&root, bind) else {
        return;
    };
    eprintln!("RUN: durable_terminal_cleanup_removes_only_exact_empty_area_and_is_idempotent");
    let old = area.identity().clone();
    area.remove_empty();
    let replacement = root.create_area(bind).expect("replacement area");
    assert_eq!(
        root.remove_area_if_present(old),
        Err(ManagedAreaError::Unverified),
        "stale durable identity must not remove a same-name replacement"
    );
    let current = replacement.identity().clone();
    replacement.remove_empty().expect("remove replacement area");
    assert!(!root.remove_area_if_present(current).unwrap());
    let final_area = root.create_area(bind).expect("cleanup target");
    let current = final_area.identity().clone();
    assert!(
        root.remove_area_if_present(current)
            .expect("remove exact area")
    );
    assert!(
        !root
            .remove_area_if_present(final_area.identity().clone())
            .expect("already absent")
    );
}

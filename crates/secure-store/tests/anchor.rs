use gocode_secure_store::{SecureStore, SecurityAnchorV1};

fn requires_compare_and_advance(_: &dyn SecureStore) {}

#[test]
fn secure_anchor_requires_an_authenticated_compare_and_advance() {
    let _ = core::mem::size_of::<SecurityAnchorV1>();
    let _ = requires_compare_and_advance;
}

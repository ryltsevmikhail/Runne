use syn::Item;

use crate::pending_surface_allowlist::exact_admission_impl;

const ADMISSION: &str = include_str!("../../src/admission.rs");
const HELPER: &str = concat!("verify_exact_", "fault_borrowed");

fn admission_impl(source: &str) -> syn::ItemImpl {
    syn::parse_file(source)
        .expect("valid admission source")
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Impl(item)
                if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("PendingQualificationAdmission")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .expect("admission implementation")
}

#[test]
fn private_fault_helper_visibility_is_exact() {
    assert!(exact_admission_impl(
        &admission_impl(ADMISSION),
        "admission.rs"
    ));
    for visibility in ["pub(crate) ", "pub(super) "] {
        let source = ADMISSION.replacen(
            &format!("fn {HELPER}("),
            &format!("{visibility}fn {HELPER}("),
            1,
        );
        assert!(!exact_admission_impl(
            &admission_impl(&source),
            "admission.rs"
        ));
    }
}

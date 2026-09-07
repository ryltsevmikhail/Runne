use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

pub(super) fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || attribute.path().is_ident("cfg") && cfg_is_test_only(&attribute.meta)
    })
}

fn cfg_is_test_only(meta: &Meta) -> bool {
    let Meta::List(list) = meta else { return false };
    let Ok(nested) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return false;
    };
    if list.path.is_ident("any") {
        nested.iter().all(cfg_is_test_predicate)
    } else {
        nested.iter().any(cfg_is_test_predicate)
    }
}

fn cfg_is_test_predicate(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|items| items.iter().any(cfg_is_test_predicate)),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|items| items.iter().all(cfg_is_test_predicate)),
        Meta::List(list) if list.path.is_ident("not") => false,
        Meta::NameValue(_) | Meta::List(_) => false,
    }
}

pub(super) fn parse_source(source: &str) -> syn::File {
    if let Ok(file) = syn::parse_file(source) {
        return file;
    }
    for wrapped in [
        format!("fn __runne_guard_wrapper() {{\n{source}\n}}"),
        format!("mod __runne_guard_wrapper {{\n{source}\n}}"),
    ] {
        if let Ok(file) = syn::parse_file(&wrapped) {
            return file;
        }
    }
    panic!("production source must parse")
}

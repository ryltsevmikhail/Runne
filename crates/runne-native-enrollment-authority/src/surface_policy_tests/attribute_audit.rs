#![cfg(test)]

use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Item, ItemMod, Lit, Meta, PathArguments, Token};

pub(super) fn item_authored_derive(item: &Item) -> bool {
    let attributes = match item {
        Item::Enum(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        _ => return false,
    };
    attributes.iter().any(attribute_authored_derive)
}

pub(super) fn module_has_forbidden_path(item: &ItemMod) -> bool {
    let path_count: usize = item
        .attrs
        .iter()
        .map(|attribute| meta_path_count(&attribute.meta))
        .sum();
    path_count != 0
        && !(path_count == 1
            && normalized_ident(&item.ident) == "tests"
            && item.attrs.iter().any(is_exact_test_cfg)
            && item.attrs.iter().any(is_exact_test_path))
}

pub(super) fn has_exact_macos_cfg(attributes: &[Attribute]) -> bool {
    let relevant: Vec<_> = attributes
        .iter()
        .filter(|attribute| {
            matches!(
                meta_name(&attribute.meta).as_deref(),
                Some("cfg" | "cfg_attr" | "path")
            )
        })
        .collect();
    relevant.len() == 1 && is_exact_macos_cfg(relevant[0])
}

pub(super) fn has_cfg_or_path_substitution(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| meta_has_cfg_or_path_substitution(&attribute.meta))
}

fn attribute_authored_derive(attribute: &Attribute) -> bool {
    meta_authored_derive(&attribute.meta)
}

fn meta_authored_derive(meta: &Meta) -> bool {
    if meta_name(meta).as_deref() == Some("derive") {
        return true;
    }
    if meta_name(meta).as_deref() != Some("cfg_attr") {
        return false;
    }
    let Meta::List(list) = meta else {
        return true;
    };
    let nested = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated);
    let Ok(nested) = nested else {
        return true;
    };
    nested.iter().skip(1).any(meta_authored_derive)
}

fn meta_path_count(meta: &Meta) -> usize {
    if meta_name(meta).as_deref() == Some("path") {
        return 1;
    }
    if meta_name(meta).as_deref() != Some("cfg_attr") {
        return 0;
    }
    let Meta::List(list) = meta else { return 1 };
    let nested = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated);
    let Ok(nested) = nested else { return 1 };
    nested.iter().skip(1).map(meta_path_count).sum()
}

fn meta_has_cfg_or_path_substitution(meta: &Meta) -> bool {
    match meta_name(meta).as_deref() {
        Some("cfg" | "path") => true,
        Some("cfg_attr") => {
            let Meta::List(list) = meta else { return true };
            list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .map_or(true, |nested| {
                    nested.iter().skip(1).any(meta_has_cfg_or_path_substitution)
                })
        }
        _ => false,
    }
}

fn is_exact_test_cfg(attribute: &Attribute) -> bool {
    let Meta::List(list) = &attribute.meta else {
        return false;
    };
    meta_name(&attribute.meta).as_deref() == Some("cfg")
        && list.parse_args::<Meta>().is_ok_and(|meta| {
            matches!(meta, Meta::Path(_)) && meta_name(&meta).as_deref() == Some("test")
        })
}

fn is_exact_macos_cfg(attribute: &Attribute) -> bool {
    let Meta::List(list) = &attribute.meta else {
        return false;
    };
    if meta_name(&attribute.meta).as_deref() != Some("cfg") {
        return false;
    }
    let Ok(Meta::NameValue(value)) = list.parse_args::<Meta>() else {
        return false;
    };
    let Expr::Lit(expression) = &value.value else {
        return false;
    };
    value.path.leading_colon.is_none()
        && value.path.segments.len() == 1
        && normalized_ident(&value.path.segments[0].ident) == "target_os"
        && matches!(value.path.segments[0].arguments, PathArguments::None)
        && expression.attrs.is_empty()
        && matches!(&expression.lit, Lit::Str(value) if value.value() == "macos")
}

fn is_exact_test_path(attribute: &Attribute) -> bool {
    let Meta::NameValue(value) = &attribute.meta else {
        return false;
    };
    let Expr::Lit(value) = &value.value else {
        return false;
    };
    meta_name(&attribute.meta).as_deref() == Some("path")
        && matches!(&value.lit, Lit::Str(path) if path.value() == "session_tests.rs")
}

fn meta_name(meta: &Meta) -> Option<String> {
    meta.path()
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .map(|name| name.trim_start_matches("r#").to_owned())
}

fn normalized_ident(value: &syn::Ident) -> String {
    value.to_string().trim_start_matches("r#").to_owned()
}

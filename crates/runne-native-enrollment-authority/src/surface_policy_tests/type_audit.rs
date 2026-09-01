#![cfg(test)]

use syn::{Fields, PathArguments, Type, Visibility};

use super::{HANDOFF, HANDOFF_MODULE, OPAQUE_TYPES, PINNED, attribute_audit};

pub(super) fn is_exact_native_wrapper(item: &syn::ItemStruct, name: &str) -> bool {
    if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
        return false;
    }
    let Fields::Named(fields) = &item.fields else {
        return false;
    };
    let Some(field) = fields.named.first() else {
        return false;
    };
    let expected = match name {
        HANDOFF => "MacOsUntrustedWriterEndpointHandoffV1",
        PINNED => "MacOsPendingProvisionalWriterSessionV1",
        _ => return false,
    };
    fields.named.len() == 1
        && matches!(field.vis, Visibility::Inherited)
        && !attribute_audit::has_cfg_or_path_substitution(&field.attrs)
        && type_path_is_exact(&field.ty, &["runne_macos_process_identity", expected])
}

pub(super) fn opaque_module(name: &str) -> &'static str {
    if matches!(name, HANDOFF | PINNED) {
        HANDOFF_MODULE
    } else {
        "session"
    }
}

pub(super) fn type_opaque_name(value: &Type) -> Option<&'static str> {
    let Type::Path(path) = value else {
        return None;
    };
    path.path
        .segments
        .last()
        .and_then(|segment| opaque_name(&normalized_ident(&segment.ident)))
}

pub(super) fn opaque_name(value: &str) -> Option<&'static str> {
    OPAQUE_TYPES.into_iter().find(|name| *name == value)
}

fn type_path_is_exact(value: &Type, expected: &[&str]) -> bool {
    let Type::Path(path) = value else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| {
                normalized_ident(&segment.ident) == *expected
                    && matches!(segment.arguments, PathArguments::None)
            })
}

fn normalized_ident(value: &syn::Ident) -> String {
    value.to_string().trim_start_matches("r#").to_owned()
}

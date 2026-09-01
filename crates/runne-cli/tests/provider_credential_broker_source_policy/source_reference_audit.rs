use std::path::{Component, Path};

use syn::{Attribute, Expr, Lit, LitStr, Macro, Meta};

pub fn path_attribute_violation(attribute: &Attribute) -> Option<String> {
    if attribute.path().is_ident("cfg_attr") {
        let Meta::List(list) = &attribute.meta else {
            return None;
        };
        return token_stream_contains_ident(list.tokens.clone(), "path")
            .then(|| "conditional path attribute is forbidden".to_owned());
    }
    if !attribute.path().is_ident("path") {
        return None;
    }
    let Meta::NameValue(value) = &attribute.meta else {
        return Some("path attribute must contain one literal".to_owned());
    };
    let Expr::Lit(expression) = &value.value else {
        return Some("path attribute must contain one literal".to_owned());
    };
    let Lit::Str(path) = &expression.lit else {
        return Some("path attribute must contain one literal".to_owned());
    };
    reference_violation("path attribute", &path.value(), &["rs"])
}

pub fn include_reference_violation(node: &Macro) -> Option<String> {
    if !node.path.is_ident("include") {
        return None;
    }
    let Ok(path) = syn::parse2::<LitStr>(node.tokens.clone()) else {
        return Some("include reference must contain one literal".to_owned());
    };
    reference_violation("include reference", &path.value(), &["rs", "inc"])
}

fn reference_violation(kind: &str, value: &str, extensions: &[&str]) -> Option<String> {
    let path = Path::new(value);
    let bytes = value.as_bytes();
    let has_windows_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if path.is_absolute()
        || value.contains('\\')
        || has_windows_prefix
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return Some(format!("{kind} escapes production source root"));
    }
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extensions.contains(&extension))
    {
        return Some(format!("{kind} has unsupported source extension"));
    }
    None
}

fn token_stream_contains_ident(tokens: proc_macro2::TokenStream, expected: &str) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => identifier == expected,
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_ident(group.stream(), expected)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

use std::path::{Component, Path};

use syn::{Attribute, Expr, Lit, LitStr, Macro, Meta};

const SOURCE_REFERENCE_MACROS: &[&str] = &["include", "include_str", "include_bytes"];

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

pub fn macro_token_source_reference_violation(tokens: proc_macro2::TokenStream) -> Option<String> {
    let trees: Vec<_> = tokens.into_iter().collect();
    for (index, token) in trees.iter().enumerate() {
        match token {
            proc_macro2::TokenTree::Ident(identifier)
                if SOURCE_REFERENCE_MACROS.contains(&identifier.to_string().as_str()) =>
            {
                return Some(format!("nested {identifier} macro"));
            }
            proc_macro2::TokenTree::Punct(mark)
                if mark.as_char() == '#'
                    && trees.get(index + 1).is_some_and(is_path_attribute_group) =>
            {
                return Some("macro-emitted path attribute".to_owned());
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(violation) = macro_token_source_reference_violation(group.stream()) {
                    return Some(violation);
                }
            }
            proc_macro2::TokenTree::Ident(_)
            | proc_macro2::TokenTree::Punct(_)
            | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
    None
}

fn is_path_attribute_group(token: &proc_macro2::TokenTree) -> bool {
    let proc_macro2::TokenTree::Group(group) = token else {
        return false;
    };
    if group.delimiter() != proc_macro2::Delimiter::Bracket {
        return false;
    }
    let tokens: Vec<_> = group.stream().into_iter().collect();
    let Some(proc_macro2::TokenTree::Ident(attribute)) = tokens.first() else {
        return false;
    };
    if attribute == "path" {
        return tokens.get(1).is_some_and(
            |next| matches!(next, proc_macro2::TokenTree::Punct(mark) if mark.as_char() == '='),
        );
    }
    attribute == "cfg_attr"
        && tokens.iter().any(|token| {
            matches!(token, proc_macro2::TokenTree::Group(arguments) if contains_path_assignment(arguments.stream()))
        })
}

fn contains_path_assignment(tokens: proc_macro2::TokenStream) -> bool {
    let trees: Vec<_> = tokens.into_iter().collect();
    trees.windows(2).any(|pair| {
        matches!(&pair[0], proc_macro2::TokenTree::Ident(identifier) if identifier == "path")
            && matches!(&pair[1], proc_macro2::TokenTree::Punct(mark) if mark.as_char() == '=')
    })
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

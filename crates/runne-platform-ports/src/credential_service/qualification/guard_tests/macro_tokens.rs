use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};

use super::syntax::normalized_ident;

#[path = "macro_token_provenance.rs"]
mod macro_token_provenance;
pub(super) use macro_token_provenance::{
    macro_attribute_names, qualified_attribute_roots, qualified_macro_roots,
};

pub(super) fn macro_mentions_qualification(tokens: &TokenStream) -> bool {
    macro_mentions_carrier(tokens) || macro_contains_opaque_expansion(tokens)
}

pub(super) fn macro_mentions_carrier(tokens: &TokenStream) -> bool {
    mentions_concrete_qualification(tokens)
        || macro_mentions_names(
            tokens,
            &BTreeSet::from(["CredentialServiceQualificationPort".to_owned()]),
        )
}

fn mentions_concrete_qualification(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let direct = tokens.iter().enumerate().any(|(index, token)| {
        let TokenTree::Ident(ident) = token else {
            return false;
        };
        if normalized_ident(ident) != "qualify" {
            return false;
        }
        if matches!(
            index.checked_sub(1).and_then(|previous| tokens.get(previous)),
            Some(TokenTree::Punct(dollar)) if dollar.as_char() == '$'
        ) {
            return false;
        }
        !matches!(
            index.checked_sub(3).and_then(|start| tokens.get(start..index)),
            Some([TokenTree::Punct(dollar), TokenTree::Ident(_), TokenTree::Punct(dot)])
                if dollar.as_char() == '$' && dot.as_char() == '.'
        )
    });
    direct
        || tokens.iter().any(|token| match token {
            TokenTree::Group(group) => mentions_concrete_qualification(&group.stream()),
            _ => false,
        })
}

pub(super) fn macro_mentions_variable_qualification(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.windows(4).any(|window| {
        matches!(window, [TokenTree::Punct(dollar), TokenTree::Ident(_), TokenTree::Punct(dot), TokenTree::Ident(method)]
            if dollar.as_char() == '$' && dot.as_char() == '.' && normalized_ident(method) == "qualify")
    }) || tokens.iter().any(|token| match token {
        TokenTree::Group(group) => macro_mentions_variable_qualification(&group.stream()),
        _ => false,
    })
}

pub(super) fn macro_contains_opaque_expansion(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let qualified_macro = tokens.windows(5).any(|window| {
        matches!(window, [TokenTree::Ident(root), TokenTree::Punct(a), TokenTree::Punct(b), TokenTree::Ident(name), TokenTree::Punct(c)]
            if a.as_char() == ':' && b.as_char() == ':' && c.as_char() == '!'
                && !trusted_qualified_macro(&normalized_ident(root), &normalized_ident(name)))
    });
    let source_edge = tokens
        .iter()
        .any(|token| matches!(token, TokenTree::Ident(ident) if normalized_ident(ident) == "mod"));
    let opaque_attribute = tokens.windows(2).any(|window| {
        matches!(window, [TokenTree::Punct(punct), TokenTree::Group(group)] if punct.as_char() == '#'
            && group.delimiter() == proc_macro2::Delimiter::Bracket
            && attribute_tokens_are_opaque(&group.stream()))
    });
    qualified_macro
        || source_edge
        || opaque_attribute
        || tokens.iter().any(|token| match token {
            TokenTree::Group(group) => macro_contains_opaque_expansion(&group.stream()),
            _ => false,
        })
}

pub(super) fn macro_contains_untrusted_nested_call(tokens: &TokenStream) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let qualified = flat.windows(5).any(|window| {
        matches!(window, [TokenTree::Ident(root), TokenTree::Punct(a), TokenTree::Punct(b), TokenTree::Ident(name), TokenTree::Punct(c)]
            if a.as_char() == ':' && b.as_char() == ':' && c.as_char() == '!'
                && !trusted_qualified_macro(&normalized_ident(root), &normalized_ident(name)))
    });
    let bare = flat.windows(2).any(|window| {
        matches!(window, [TokenTree::Ident(name), TokenTree::Punct(punct)]
            if punct.as_char() == '!'
                && normalized_ident(name) != "if"
                && !super::macro_definitions::is_compiler_builtin_macro(&normalized_ident(name))
                && super::macro_trust::trusted_bare_root(&normalized_ident(name)).is_none())
    });
    qualified
        || bare
        || flat.iter().any(|token| match token {
            TokenTree::Group(group) => macro_contains_untrusted_nested_call(&group.stream()),
            _ => false,
        })
}

#[path = "macro_import_tokens.rs"]
mod macro_import_tokens;
pub(super) use macro_import_tokens::{macro_contains_import_item, payload_contains_import_escape};
#[path = "macro_fragment_validation.rs"]
mod macro_fragment_validation;
#[path = "macro_import_context.rs"]
mod macro_import_context;
#[path = "macro_invocation_match.rs"]
mod macro_invocation_match;
#[path = "macro_token_key.rs"]
mod macro_token_key;
pub(super) use macro_invocation_match::{
    macro_invocation_forwards_qualification, macro_invocation_has_dynamic_import,
};

fn attribute_tokens_are_opaque(tokens: &TokenStream) -> bool {
    let first = tokens.clone().into_iter().find_map(|token| match token {
        TokenTree::Ident(ident) => Some(normalized_ident(&ident)),
        _ => None,
    });
    if first.as_deref().is_some_and(|name| {
        matches!(
            name,
            "allow"
                | "cfg"
                | "deprecated"
                | "deny"
                | "doc"
                | "expect"
                | "forbid"
                | "must_use"
                | "macro_export"
                | "non_exhaustive"
                | "repr"
                | "serde"
                | "warn"
        )
    }) {
        return false;
    }
    let Ok(meta) = syn::parse2::<syn::Meta>(tokens.clone()) else {
        return true;
    };
    if meta.path().segments.len() > 1 {
        return true;
    }
    let name = meta
        .path()
        .get_ident()
        .map(super::syntax::normalized_ident)
        .unwrap_or_default();
    if name == "derive" {
        let syn::Meta::List(list) = meta else {
            return true;
        };
        let Ok(paths) = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        ) else {
            return true;
        };
        return paths.iter().any(|path| {
            let allowed_name = path.segments.last().is_some_and(|segment| {
                matches!(
                    normalized_ident(&segment.ident).as_str(),
                    "Clone"
                        | "Copy"
                        | "Debug"
                        | "Default"
                        | "Deserialize"
                        | "Eq"
                        | "Error"
                        | "Hash"
                        | "Ord"
                        | "PartialEq"
                        | "PartialOrd"
                        | "Serialize"
                )
            });
            let trusted_qualified = path.segments.len() == 1
                || matches!(
                    (path.segments.first(), path.segments.last()),
                    (Some(root), Some(name))
                        if matches!(
                            (normalized_ident(&root.ident).as_str(), normalized_ident(&name.ident).as_str()),
                            ("serde", "Serialize" | "Deserialize") | ("thiserror", "Error")
                        )
                );
            !allowed_name || !trusted_qualified
        });
    }
    !matches!(
        name.as_str(),
        "allow"
            | "cfg"
            | "deprecated"
            | "deny"
            | "doc"
            | "expect"
            | "forbid"
            | "must_use"
            | "macro_export"
            | "non_exhaustive"
            | "repr"
            | "serde"
            | "warn"
    )
}

fn trusted_qualified_macro(root: &str, name: &str) -> bool {
    matches!(
        (root, name),
        ("std", "matches" | "include" | "thread_local")
            | ("mem", "offset_of")
            | ("serde_json", "json")
            | ("tokio", "join" | "pin" | "select" | "test")
            | ("tracing" | "log", "error" | "info")
    )
}

pub(super) fn macro_mentions_names(tokens: &TokenStream, names: &BTreeSet<String>) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.iter().enumerate().any(|(index, token)| match token {
        TokenTree::Ident(identifier) => {
            names.contains(&normalized_ident(identifier))
                && !matches!(
                    index.checked_sub(1).and_then(|previous| tokens.get(previous)),
                    Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == '$'
                )
        }
        TokenTree::Group(group) => macro_mentions_names(&group.stream(), names),
        _ => false,
    })
}

pub(super) fn named_macro_calls(tokens: &TokenStream) -> BTreeSet<String> {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut calls = BTreeSet::new();
    for pair in tokens.windows(2) {
        if let [TokenTree::Ident(name), TokenTree::Punct(punctuation)] = pair
            && punctuation.as_char() == '!'
        {
            calls.insert(normalized_ident(name));
        }
    }
    for token in tokens {
        if let TokenTree::Group(group) = token {
            calls.extend(named_macro_calls(&group.stream()));
        }
    }
    calls
}

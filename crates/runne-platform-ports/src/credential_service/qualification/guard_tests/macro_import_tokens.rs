use super::super::syntax::normalized_ident;
use super::{qualified_attribute_roots, qualified_macro_roots};
use proc_macro2::{TokenStream, TokenTree};

pub fn macro_contains_import_item(tokens: &TokenStream) -> bool {
    macro_arms(tokens)
        .into_iter()
        .any(|(_, transcriber)| raw_tokens_contain_import(&transcriber))
}

pub fn payload_contains_import_escape(tokens: &TokenStream) -> bool {
    raw_tokens_contain_import(tokens)
        && (contains_trusted_escape(tokens) || contains_trusted_bare_call(tokens))
}

fn contains_trusted_bare_call(tokens: &TokenStream) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    flat.windows(2).any(|pair| {
        matches!(pair, [TokenTree::Ident(name), TokenTree::Punct(bang)]
            if bang.as_char() == '!'
                && super::super::macro_trust::trusted_bare_root(&normalized_ident(name)).is_some())
    }) || flat.iter().any(|token| match token {
        TokenTree::Group(group) => contains_trusted_bare_call(&group.stream()),
        _ => false,
    })
}

fn raw_tokens_contain_import(tokens: &TokenStream) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    flat.iter()
        .any(|token| matches!(token, TokenTree::Ident(name) if is_keyword(name, "use")))
        || flat.windows(2).any(|pair| {
            matches!(pair, [TokenTree::Ident(external), TokenTree::Ident(krate)]
                if is_keyword(external, "extern") && is_keyword(krate, "crate"))
        })
        || flat.iter().any(|token| match token {
            TokenTree::Group(group) => raw_tokens_contain_import(&group.stream()),
            _ => false,
        })
}

fn is_keyword(ident: &proc_macro2::Ident, expected: &str) -> bool {
    ident == expected && !ident.to_string().starts_with("r#")
}

pub(super) fn macro_arms(tokens: &TokenStream) -> Vec<(TokenStream, TokenStream)> {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut arms = Vec::new();
    let mut index = 0;
    while index + 3 < flat.len() {
        if let (
            TokenTree::Group(matcher),
            TokenTree::Punct(eq),
            TokenTree::Punct(gt),
            TokenTree::Group(transcriber),
        ) = (
            &flat[index],
            &flat[index + 1],
            &flat[index + 2],
            &flat[index + 3],
        ) && eq.as_char() == '='
            && gt.as_char() == '>'
        {
            arms.push((matcher.stream(), transcriber.stream()));
            index += 4;
        } else {
            index += 1;
        }
    }
    if arms.is_empty()
        && let Some(TokenTree::Group(body)) = flat.iter().find(|token| {
            matches!(token, TokenTree::Group(group) if group.delimiter() == proc_macro2::Delimiter::Brace)
        })
    {
        return macro_arms(&body.stream());
    }
    arms
}

fn contains_trusted_escape(tokens: &TokenStream) -> bool {
    qualified_macro_roots(tokens)
        .into_iter()
        .chain(qualified_attribute_roots(tokens))
        .any(|root| {
            matches!(
                root.as_str(),
                "log" | "mem" | "serde" | "serde_json" | "std" | "thiserror" | "tokio" | "tracing"
            )
        })
}

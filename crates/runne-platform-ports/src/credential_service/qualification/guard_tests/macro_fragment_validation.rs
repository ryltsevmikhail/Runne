use proc_macro2::{TokenStream, TokenTree};
use syn::parse::Parser;

use super::super::syntax::normalized_ident;

pub(super) fn fragment_is_valid(kind: &str, tokens: &[TokenTree]) -> bool {
    let stream = tokens.iter().cloned().collect::<TokenStream>();
    match kind {
        "block" => syn::parse2::<syn::Block>(stream).is_ok(),
        "expr" => syn::parse2::<syn::Expr>(stream).is_ok(),
        "expr_2021" => syn::parse2::<syn::Expr>(stream)
            .is_ok_and(|expr| !matches!(expr, syn::Expr::Const(_) | syn::Expr::Infer(_))),
        "item" => syn::parse2::<syn::Item>(stream).is_ok(),
        "lifetime" => syn::parse2::<syn::Lifetime>(stream).is_ok(),
        "literal" => syn::parse2::<syn::Lit>(stream).is_ok(),
        "meta" => syn::parse2::<syn::Meta>(stream).is_ok(),
        "path" => syn::parse2::<syn::Path>(stream).is_ok(),
        "pat" => syn::Pat::parse_multi_with_leading_vert
            .parse2(stream)
            .is_ok(),
        "pat_param" => syn::Pat::parse_single.parse2(stream).is_ok(),
        "stmt" => syn::Block::parse_within
            .parse2(stream)
            .is_ok_and(|statements| statements.len() == 1),
        "ty" => syn::parse2::<syn::Type>(stream).is_ok(),
        "vis" => syn::parse2::<syn::Visibility>(stream).is_ok(),
        _ => true,
    }
}

pub(super) fn body_contains_metavariable(tokens: &TokenStream) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    flat.windows(2).any(|pair| {
        matches!(pair, [TokenTree::Punct(dollar), TokenTree::Ident(_)] if dollar.as_char() == '$')
    }) || flat.iter().any(|token| match token {
        TokenTree::Group(group) => body_contains_metavariable(&group.stream()),
        _ => false,
    })
}

pub(super) fn tokens_contain_carrier(tokens: &[TokenTree]) -> bool {
    tokens.iter().any(|token| match token {
        TokenTree::Ident(ident) => matches!(
            normalized_ident(ident).as_str(),
            "qualify" | "CredentialServiceQualificationPort"
        ),
        TokenTree::Group(group) => {
            tokens_contain_carrier(&group.stream().into_iter().collect::<Vec<_>>())
        }
        _ => false,
    })
}

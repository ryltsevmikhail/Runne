use proc_macro2::TokenTree;

use super::super::syntax::normalized_ident;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TokenKey {
    Ident(String),
    Literal(String),
    Punct { character: char, joint: bool },
}

pub(super) fn token_key(token: &TokenTree) -> Option<TokenKey> {
    match token {
        TokenTree::Ident(ident) => Some(TokenKey::Ident(normalized_ident(ident))),
        TokenTree::Literal(literal) => Some(TokenKey::Literal(literal.to_string())),
        TokenTree::Punct(punct) => Some(TokenKey::Punct {
            character: punct.as_char(),
            joint: punct.spacing() == proc_macro2::Spacing::Joint,
        }),
        TokenTree::Group(_) => None,
    }
}

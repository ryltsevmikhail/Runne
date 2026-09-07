use std::collections::HashSet;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

pub(super) fn macro_target_reference_present(tokens: TokenStream, known: &HashSet<String>) -> bool {
    macro_target_matches(tokens, known).0
}

pub(super) fn macro_target_call_count(tokens: TokenStream, known: &HashSet<String>) -> usize {
    macro_target_matches(tokens, known).1
}

fn macro_target_matches(tokens: TokenStream, known: &HashSet<String>) -> (bool, usize) {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    let mut found = false;
    let mut calls = 0;
    for index in 0..tokens.len() {
        let method_index = if index + 4 < tokens.len()
            && punct(&tokens[index], '<')
            && ident_known(&tokens[index + 1], known)
            && punct(&tokens[index + 2], '>')
            && punct(&tokens[index + 3], ':')
            && punct(&tokens[index + 4], ':')
        {
            Some(index + 5)
        } else if index + 2 < tokens.len()
            && ident_known(&tokens[index], known)
            && punct(&tokens[index + 1], ':')
            && punct(&tokens[index + 2], ':')
        {
            Some(index + 3)
        } else {
            None
        };
        if let Some(method_index) = method_index
            && method_index < tokens.len()
            && let TokenTree::Ident(method) = &tokens[method_index]
            && matches!(
                method.to_string().as_str(),
                "capture_current" | "verify_exact"
            )
        {
            found = true;
            if matches!(tokens.get(method_index + 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis)
            {
                calls += 1;
            }
        }
        if let TokenTree::Group(group) = &tokens[index] {
            let nested = macro_target_matches(group.stream(), known);
            found |= nested.0;
            calls += nested.1;
        }
    }
    (found, calls)
}

fn ident_known(token: &TokenTree, known: &HashSet<String>) -> bool {
    matches!(token, TokenTree::Ident(ident) if known.contains(&ident.to_string()))
}

fn punct(token: &TokenTree, expected: char) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == expected)
}

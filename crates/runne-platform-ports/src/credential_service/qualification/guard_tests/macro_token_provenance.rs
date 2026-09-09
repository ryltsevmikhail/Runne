use proc_macro2::{TokenStream, TokenTree};

use super::super::syntax::normalized_ident;

pub fn macro_attribute_names(
    tokens: &proc_macro2::TokenStream,
) -> std::collections::BTreeSet<String> {
    fn collect(stream: proc_macro2::TokenStream, names: &mut std::collections::BTreeSet<String>) {
        let tokens = stream.into_iter().collect::<Vec<_>>();
        for (index, token) in tokens.iter().enumerate() {
            if matches!(token, proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '#')
                && let Some(proc_macro2::TokenTree::Group(attribute)) = tokens.get(index + 1)
                && attribute.delimiter() == proc_macro2::Delimiter::Bracket
            {
                let attribute_tokens = attribute.stream().into_iter().collect::<Vec<_>>();
                if let Some(proc_macro2::TokenTree::Ident(name)) = attribute_tokens.first() {
                    let name = normalized_ident(name);
                    if name == "derive" {
                        if let Some(proc_macro2::TokenTree::Group(arguments)) =
                            attribute_tokens.get(1)
                        {
                            names.extend(arguments.stream().into_iter().filter_map(|token| {
                                let proc_macro2::TokenTree::Ident(name) = token else {
                                    return None;
                                };
                                Some(normalized_ident(&name))
                            }));
                        }
                    } else {
                        names.insert(name);
                    }
                }
            }
            if let proc_macro2::TokenTree::Group(group) = token {
                collect(group.stream(), names);
            }
        }
    }

    let mut names = std::collections::BTreeSet::new();
    collect(tokens.clone(), &mut names);
    names
}

pub fn qualified_macro_roots(tokens: &TokenStream) -> std::collections::BTreeSet<String> {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut roots = flat
        .windows(5)
        .filter_map(|window| match window {
            [
                TokenTree::Ident(root),
                TokenTree::Punct(first),
                TokenTree::Punct(second),
                TokenTree::Ident(_),
                TokenTree::Punct(call),
            ] if first.as_char() == ':' && second.as_char() == ':' && call.as_char() == '!' => {
                Some(normalized_ident(root))
            }
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    for token in flat {
        if let TokenTree::Group(group) = token {
            roots.extend(qualified_macro_roots(&group.stream()));
        }
    }
    roots
}

pub fn qualified_attribute_roots(tokens: &TokenStream) -> std::collections::BTreeSet<String> {
    fn roots_in_attribute(stream: TokenStream) -> std::collections::BTreeSet<String> {
        let flat = stream.into_iter().collect::<Vec<_>>();
        let mut roots = flat
            .windows(3)
            .filter_map(|window| match window {
                [
                    TokenTree::Ident(root),
                    TokenTree::Punct(first),
                    TokenTree::Punct(second),
                ] if first.as_char() == ':' && second.as_char() == ':' => {
                    Some(normalized_ident(root))
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        for token in flat {
            if let TokenTree::Group(group) = token {
                roots.extend(roots_in_attribute(group.stream()));
            }
        }
        roots
    }

    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut roots = std::collections::BTreeSet::new();
    for (index, token) in flat.iter().enumerate() {
        if matches!(token, TokenTree::Punct(marker) if marker.as_char() == '#')
            && let Some(TokenTree::Group(attribute)) = flat.get(index + 1)
            && attribute.delimiter() == proc_macro2::Delimiter::Bracket
        {
            roots.extend(roots_in_attribute(attribute.stream()));
        }
        if let TokenTree::Group(group) = token {
            roots.extend(qualified_attribute_roots(&group.stream()));
        }
    }
    roots
}

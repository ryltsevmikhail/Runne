use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{TokenStream, TokenTree};

use super::super::syntax::normalized_ident;
use super::macro_invocation_match::Pattern;

pub(super) fn dynamic_candidates(
    pattern: &[Pattern],
    body: &TokenStream,
    shadowed_macros: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut kinds = BTreeMap::new();
    collect_kinds(pattern, &mut kinds);
    kinds
        .into_iter()
        .filter_map(|(name, kind)| {
            let expansion = match kind.as_str() {
                "ident" | "tt" => {
                    reference_can_prefix_item(body, &name, shadowed_macros)
                        || reference_is_forwarded(body, &name, shadowed_macros)
                }
                "block" | "item" | "stmt" | "expr" | "expr_2021" => {
                    reference_in_expansion(body, &name, shadowed_macros)
                }
                _ => false,
            };
            expansion.then_some(name)
        })
        .collect()
}

fn reference_is_forwarded(
    tokens: &TokenStream,
    name: &str,
    shadowed_macros: &BTreeSet<String>,
) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let direct = matches!(flat.as_slice(), [TokenTree::Punct(dollar), TokenTree::Ident(ident)]
        if dollar.as_char() == '$' && normalized_ident(ident) == name);
    direct
        || flat.windows(3).any(|window| {
            matches!(window, [TokenTree::Punct(dollar), TokenTree::Group(group), TokenTree::Punct(repeat)]
                if dollar.as_char() == '$'
                    && matches!(repeat.as_char(), '*' | '+' | '?')
                    && reference_is_forwarded(&group.stream(), name, shadowed_macros))
        })
        || child_expansions(&flat, shadowed_macros)
            .any(|group| reference_is_forwarded(&group.stream(), name, shadowed_macros))
}

fn collect_kinds(pattern: &[Pattern], output: &mut BTreeMap<String, String>) {
    for item in pattern {
        match item {
            Pattern::Variable { name, kind } => {
                output.insert(name.clone(), kind.clone());
            }
            Pattern::Group(_, nested) | Pattern::Repeat { body: nested, .. } => {
                collect_kinds(nested, output);
            }
            Pattern::Literal(_) => {}
        }
    }
}

fn reference_can_prefix_item(
    tokens: &TokenStream,
    name: &str,
    shadowed_macros: &BTreeSet<String>,
) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    flat.windows(3).any(|window| {
        matches!(window, [TokenTree::Punct(dollar), TokenTree::Ident(ident), next]
            if dollar.as_char() == '$'
                && normalized_ident(ident) == name
                && (matches!(next, TokenTree::Ident(_) | TokenTree::Group(_))
                    || matches!(next, TokenTree::Punct(punct) if matches!(punct.as_char(), '$' | ':'))))
    }) || child_expansions(&flat, shadowed_macros)
        .any(|group| reference_can_prefix_item(&group.stream(), name, shadowed_macros))
}

fn reference_in_expansion(
    tokens: &TokenStream,
    name: &str,
    shadowed_macros: &BTreeSet<String>,
) -> bool {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    flat.windows(2).any(|pair| {
        matches!(pair, [TokenTree::Punct(dollar), TokenTree::Ident(ident)]
            if dollar.as_char() == '$' && normalized_ident(ident) == name)
    }) || child_expansions(&flat, shadowed_macros)
        .any(|group| reference_in_expansion(&group.stream(), name, shadowed_macros))
}

fn child_expansions<'a>(
    tokens: &'a [TokenTree],
    shadowed_macros: &'a BTreeSet<String>,
) -> impl Iterator<Item = &'a proc_macro2::Group> {
    tokens.iter().enumerate().filter_map(|(index, token)| {
        let TokenTree::Group(group) = token else {
            return None;
        };
        let is_unshadowed_builtin_payload = index > 1
            && matches!(&tokens[index - 1], TokenTree::Punct(punct) if punct.as_char() == '!')
            && matches!(&tokens[index - 2], TokenTree::Ident(name)
                if super::super::macro_definitions::is_compiler_builtin_macro(&normalized_ident(name))
                    && !shadowed_macros.contains(&normalized_ident(name)));
        (!is_unshadowed_builtin_payload).then_some(group)
    })
}

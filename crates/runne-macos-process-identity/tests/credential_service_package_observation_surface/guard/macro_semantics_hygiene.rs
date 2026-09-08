use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};

use super::super::patterns::BindingEnvironment;

pub(super) fn template_call_site_collisions(
    tokens: &TokenStream,
    environment: &BindingEnvironment,
) -> BTreeSet<String> {
    let mut collisions = BTreeSet::new();
    collect_collisions(tokens, environment, &mut collisions);
    collisions
}

fn collect_collisions(
    tokens: &TokenStream,
    environment: &BindingEnvironment,
    collisions: &mut BTreeSet<String>,
) {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut index = 0;
    while index < tokens.len() {
        if matches!(tokens.get(index), Some(TokenTree::Punct(punct)) if punct.as_char() == '$') {
            if let Some(TokenTree::Group(group)) = tokens.get(index + 1) {
                collect_collisions(&group.stream(), environment, collisions);
            }
            index += 2;
            continue;
        }
        match &tokens[index] {
            TokenTree::Ident(ident) if environment.lookup(&ident.to_string()).is_some() => {
                collisions.insert(ident.to_string());
            }
            TokenTree::Group(group) => {
                collect_collisions(&group.stream(), environment, collisions);
            }
            _ => {}
        }
        index += 1;
    }
}

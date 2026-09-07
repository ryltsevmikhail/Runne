use std::collections::HashMap;

use super::syntax::is_test_only;
use syn::LitStr;
use syn::visit::Visit;

#[derive(Default)]
pub(super) struct MacroDefinitions {
    pub(super) items: HashMap<String, Vec<IncludeTemplate>>,
}

#[derive(Clone)]
pub(super) enum IncludeTemplate {
    Literal(String),
    Forwarded,
}

impl<'ast> Visit<'ast> for MacroDefinitions {
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if is_test_only(&node.attrs) {
            return;
        }
        if let Some(name) = &node.ident {
            let templates = include_templates(node.mac.tokens.clone());
            if !templates.is_empty() {
                self.items.insert(name.to_string(), templates);
            }
        }
    }
}

pub(super) fn include_templates(tokens: proc_macro2::TokenStream) -> Vec<IncludeTemplate> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if index + 2 < tokens.len()
            && matches!(&tokens[index], proc_macro2::TokenTree::Ident(name) if name == "include")
            && matches!(&tokens[index + 1], proc_macro2::TokenTree::Punct(p) if p.as_char() == '!')
        {
            let proc_macro2::TokenTree::Group(group) = &tokens[index + 2] else {
                panic!("unsupported include macro token stream")
            };
            if let Ok(literal) = syn::parse2::<LitStr>(group.stream()) {
                result.push(IncludeTemplate::Literal(literal.value()));
            } else if is_forwarded_literal(group.stream()) {
                result.push(IncludeTemplate::Forwarded);
            } else {
                panic!("unsupported include macro argument")
            }
            index += 3;
        } else {
            if let proc_macro2::TokenTree::Group(group) = &tokens[index] {
                result.extend(include_templates(group.stream()));
            }
            index += 1;
        }
    }
    result
}

fn is_forwarded_literal(tokens: proc_macro2::TokenStream) -> bool {
    let mut iter = tokens.into_iter();
    matches!(iter.next(), Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == '$')
        && matches!(iter.next(), Some(proc_macro2::TokenTree::Ident(_)))
        && iter.next().is_none()
}

pub(super) fn include_token_present(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => ident == "include",
        proc_macro2::TokenTree::Group(group) => include_token_present(group.stream()),
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

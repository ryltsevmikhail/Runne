use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::{Attribute, Expr, ExprLit, Lit, LitStr, Meta};

use super::inventory_source_tokens::{is_source_path, source_literal_present};
use super::syntax::is_test_only;

#[derive(Clone)]
pub(super) enum ExpansionTemplate {
    Include(ArgumentTemplate),
    Module {
        name: String,
        path: Option<String>,
        test_only: bool,
    },
    Invoke {
        name: String,
        argument: ArgumentTemplate,
    },
    Unsupported(String),
}

#[derive(Clone)]
pub(super) enum ArgumentTemplate {
    Empty,
    Forwarded,
    Literal(String),
    Unsupported(bool),
}

#[derive(Clone)]
pub(super) struct MacroArm {
    pub(super) matcher: String,
    pub(super) matcher_tokens: TokenStream,
    pub(super) expansion_tokens: TokenStream,
    pub(super) templates: Vec<ExpansionTemplate>,
}

pub(super) enum ResolvedSourceEdge {
    Include(String),
    Module { name: String, path: Option<String> },
}

pub(super) fn macro_arms(tokens: TokenStream) -> Vec<MacroArm> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    let mut arms = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let Some(TokenTree::Group(matcher)) = tokens.get(index) else {
            index += 1;
            continue;
        };
        if !matches!(tokens.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '=')
            || !matches!(tokens.get(index + 2), Some(TokenTree::Punct(p)) if p.as_char() == '>')
        {
            index += 1;
            continue;
        }
        let Some(TokenTree::Group(expansion)) = tokens.get(index + 3) else {
            index += 1;
            continue;
        };
        arms.push(MacroArm {
            matcher: matcher.stream().to_string(),
            matcher_tokens: matcher.stream(),
            expansion_tokens: expansion.stream(),
            templates: expansion_templates(expansion.stream()),
        });
        index += 4;
    }
    assert!(
        !arms.is_empty(),
        "unsupported macro definition without rules"
    );
    arms
}

pub(super) fn selected_arm<'a>(arms: &'a [MacroArm], invocation: &TokenStream) -> &'a MacroArm {
    let invocation = invocation.to_string();
    let exact = arms
        .iter()
        .filter(|arm| arm.matcher == invocation)
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        return exact[0];
    }
    assert_eq!(
        arms.len(),
        1,
        "macro source edge arm selection is ambiguous"
    );
    &arms[0]
}

pub(super) fn arm_forwards_invocation(arm: &MacroArm) -> bool {
    let matcher_names = metavariable_names(arm.matcher_tokens.clone());
    let expansion_names = metavariable_names(arm.expansion_tokens.clone());
    matcher_names
        .iter()
        .any(|name| expansion_names.contains(name))
}

fn metavariable_names(tokens: TokenStream) -> Vec<String> {
    let values = tokens.into_iter().collect::<Vec<_>>();
    let mut names = values
        .windows(2)
        .filter_map(|pair| match pair {
            [TokenTree::Punct(dollar), TokenTree::Ident(name)] if dollar.as_char() == '$' => {
                Some(name.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for token in values {
        if let TokenTree::Group(group) = token {
            names.extend(metavariable_names(group.stream()));
        }
    }
    names
}

pub(super) fn expansion_templates(tokens: TokenStream) -> Vec<ExpansionTemplate> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut attributes = TokenStream::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_attribute(&tokens, index) {
            attributes.extend([tokens[index].clone(), tokens[index + 1].clone()]);
            index += 2;
            continue;
        }
        if matches!(&tokens[index], TokenTree::Ident(name) if name == "mod") {
            result.push(module_template(tokens.get(index + 1), attributes.clone()));
            attributes = TokenStream::new();
            index += 2;
            continue;
        }
        if let Some((name, group)) = macro_invocation(&tokens, index) {
            let argument = argument_template(group.stream());
            if name == "include" {
                result.push(ExpansionTemplate::Include(argument));
            } else {
                result.push(ExpansionTemplate::Invoke { name, argument });
            }
            attributes = TokenStream::new();
            index += 3;
            continue;
        }
        if let TokenTree::Group(group) = &tokens[index] {
            result.extend(expansion_templates(group.stream()));
        }
        if !matches!(&tokens[index], TokenTree::Ident(name) if name == "pub") {
            attributes = TokenStream::new();
        }
        index += 1;
    }
    result
}

fn is_attribute(tokens: &[TokenTree], index: usize) -> bool {
    matches!(tokens.get(index), Some(TokenTree::Punct(p)) if p.as_char() == '#')
        && matches!(tokens.get(index + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket)
}

fn module_template(name: Option<&TokenTree>, attributes: TokenStream) -> ExpansionTemplate {
    let Some(TokenTree::Ident(name)) = name else {
        return ExpansionTemplate::Unsupported(
            "unsupported dynamic macro-generated module edge".into(),
        );
    };
    match module_attributes(attributes) {
        Ok((path, test_only)) => ExpansionTemplate::Module {
            name: name.to_string(),
            path,
            test_only,
        },
        Err(reason) => ExpansionTemplate::Unsupported(reason),
    }
}

fn module_attributes(attributes: TokenStream) -> Result<(Option<String>, bool), String> {
    if attributes.is_empty() {
        return Ok((None, false));
    }
    let attributes = Attribute::parse_outer
        .parse2(attributes)
        .map_err(|_| "unsupported macro-generated module attributes".to_owned())?;
    let mut path = None;
    for attribute in &attributes {
        if attribute.path().is_ident("path") {
            let Meta::NameValue(value) = &attribute.meta else {
                return Err("unsupported macro-generated path attribute".into());
            };
            let Expr::Lit(ExprLit {
                lit: Lit::Str(literal),
                ..
            }) = &value.value
            else {
                return Err("unsupported macro-generated path value".into());
            };
            if path.replace(literal.value()).is_some() {
                return Err("multiple macro-generated path attributes".into());
            }
        } else if attribute.path().is_ident("cfg_attr")
            && matches!(&attribute.meta, Meta::List(list) if list.tokens.to_string().contains("path"))
        {
            return Err("conditional macro-generated path is unsupported".into());
        }
    }
    Ok((path, is_test_only(&attributes)))
}

fn macro_invocation(tokens: &[TokenTree], index: usize) -> Option<(String, &Group)> {
    let TokenTree::Ident(name) = tokens.get(index)? else {
        return None;
    };
    if !matches!(tokens.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!') {
        return None;
    }
    let Some(TokenTree::Group(group)) = tokens.get(index + 2) else {
        return None;
    };
    Some((name.to_string(), group))
}

pub(super) fn argument_template(tokens: TokenStream) -> ArgumentTemplate {
    if tokens.is_empty() {
        return ArgumentTemplate::Empty;
    }
    if let Ok(literal) = syn::parse2::<LitStr>(tokens.clone()) {
        return ArgumentTemplate::Literal(literal.value());
    }
    let values = tokens.clone().into_iter().collect::<Vec<_>>();
    if matches!(values.as_slice(), [TokenTree::Punct(p), TokenTree::Ident(_)] if p.as_char() == '$')
    {
        ArgumentTemplate::Forwarded
    } else {
        ArgumentTemplate::Unsupported(source_literal_present(tokens))
    }
}

pub(super) fn substitute_argument(
    template: &ArgumentTemplate,
    invocation: &ArgumentTemplate,
) -> ArgumentTemplate {
    match template {
        ArgumentTemplate::Forwarded => invocation.clone(),
        other => other.clone(),
    }
}

pub(super) fn resolve_argument(
    template: &ArgumentTemplate,
    invocation: &ArgumentTemplate,
) -> Option<String> {
    match substitute_argument(template, invocation) {
        ArgumentTemplate::Literal(path) => Some(path),
        ArgumentTemplate::Empty
        | ArgumentTemplate::Forwarded
        | ArgumentTemplate::Unsupported(_) => None,
    }
}

pub(super) fn argument_may_name_source(argument: &ArgumentTemplate) -> bool {
    match argument {
        ArgumentTemplate::Literal(path) => is_source_path(path),
        ArgumentTemplate::Unsupported(source_like) => *source_like,
        ArgumentTemplate::Empty | ArgumentTemplate::Forwarded => false,
    }
}

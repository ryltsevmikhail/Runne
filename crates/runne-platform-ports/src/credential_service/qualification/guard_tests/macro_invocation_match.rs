use std::collections::BTreeMap;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

use super::super::syntax::normalized_ident;
use super::macro_fragment_validation::{
    body_contains_metavariable, fragment_is_valid, tokens_contain_carrier,
};
use super::macro_import_context::dynamic_candidates;
use super::macro_import_tokens::macro_arms;
use super::macro_token_key::{TokenKey, token_key};

pub fn macro_invocation_has_dynamic_import(
    definition: &TokenStream,
    invocation: &TokenStream,
    shadowed_macros: &std::collections::BTreeSet<String>,
) -> bool {
    let input = invocation.clone().into_iter().collect::<Vec<_>>();
    for (matcher, body) in macro_arms(definition) {
        let Some(pattern) = parse_sequence(&matcher) else {
            return body_contains_metavariable(&body) && tokens_contain_import(&input);
        };
        let complete = match_sequence(&pattern, &input, 0)
            .into_iter()
            .filter(|matched| matched.position == input.len())
            .collect::<Vec<_>>();
        if !complete.is_empty() {
            let candidates = dynamic_candidates(&pattern, &body, shadowed_macros);
            return complete.iter().any(|matched| {
                candidates.iter().any(|name| {
                    matched.bindings.get(name).is_some_and(|values| {
                        values.iter().any(|tokens| tokens_contain_import(tokens))
                    })
                })
            });
        }
    }
    false
}

pub fn macro_invocation_forwards_qualification(
    definition: &TokenStream,
    invocation: &TokenStream,
    shadowed_macros: &std::collections::BTreeSet<String>,
) -> bool {
    let input = invocation.clone().into_iter().collect::<Vec<_>>();
    for (matcher, body) in macro_arms(definition) {
        let Some(pattern) = parse_sequence(&matcher) else {
            return body_contains_metavariable(&body) && tokens_contain_carrier(&input);
        };
        let complete = match_sequence(&pattern, &input, 0)
            .into_iter()
            .filter(|matched| matched.position == input.len())
            .collect::<Vec<_>>();
        if !complete.is_empty() {
            let candidates = dynamic_candidates(&pattern, &body, shadowed_macros);
            return complete.iter().any(|matched| {
                candidates.iter().any(|name| {
                    matched.bindings.get(name).is_some_and(|values| {
                        values.iter().any(|tokens| tokens_contain_carrier(tokens))
                    })
                })
            });
        }
    }
    false
}

#[derive(Clone)]
pub(super) enum Pattern {
    Literal(TokenKey),
    Group(Delimiter, Vec<Self>),
    Variable {
        name: String,
        kind: String,
    },
    Repeat {
        body: Vec<Self>,
        separator: Vec<TokenKey>,
        minimum: usize,
        maximum: Option<usize>,
    },
}

fn parse_sequence(tokens: &TokenStream) -> Option<Vec<Pattern>> {
    let flat = tokens.clone().into_iter().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = 0;
    while index < flat.len() {
        if matches!(&flat[index], TokenTree::Punct(punct) if punct.as_char() == '$') {
            match flat.get(index + 1) {
                Some(TokenTree::Ident(name)) if matches!(flat.get(index + 2), Some(TokenTree::Punct(colon)) if colon.as_char() == ':') =>
                {
                    let Some(TokenTree::Ident(kind)) = flat.get(index + 3) else {
                        return None;
                    };
                    result.push(Pattern::Variable {
                        name: normalized_ident(name),
                        kind: normalized_ident(kind),
                    });
                    index += 4;
                    continue;
                }
                Some(TokenTree::Group(group)) => {
                    let body = parse_sequence(&group.stream())?;
                    let operator_index = (index + 2..flat.len()).find(|candidate| {
                        matches!(&flat[*candidate], TokenTree::Punct(operator) if matches!(operator.as_char(), '*' | '+' | '?'))
                    })?;
                    let separator = flat[index + 2..operator_index]
                        .iter()
                        .map(token_key)
                        .collect::<Option<Vec<_>>>()?;
                    let TokenTree::Punct(operator) = &flat[operator_index] else {
                        return None;
                    };
                    result.push(Pattern::Repeat {
                        body,
                        separator,
                        minimum: usize::from(operator.as_char() == '+'),
                        maximum: (operator.as_char() == '?').then_some(1),
                    });
                    index = operator_index + 1;
                    continue;
                }
                _ => return None,
            }
        }
        match &flat[index] {
            TokenTree::Group(group) => result.push(Pattern::Group(
                group.delimiter(),
                parse_sequence(&group.stream())?,
            )),
            token => result.push(Pattern::Literal(token_key(token)?)),
        }
        index += 1;
    }
    Some(result)
}

#[derive(Clone, Default)]
struct Match {
    position: usize,
    bindings: BTreeMap<String, Vec<Vec<TokenTree>>>,
}

fn match_sequence(pattern: &[Pattern], input: &[TokenTree], start: usize) -> Vec<Match> {
    let initial = Match {
        position: start,
        bindings: BTreeMap::new(),
    };
    pattern.iter().fold(vec![initial], |states, item| {
        states
            .into_iter()
            .flat_map(|state| match_item(item, input, state))
            .collect()
    })
}

fn match_item(item: &Pattern, input: &[TokenTree], state: Match) -> Vec<Match> {
    match item {
        Pattern::Literal(expected) => input
            .get(state.position)
            .filter(|token| token_key(token).as_ref() == Some(expected))
            .map(|_| Match {
                position: state.position + 1,
                ..state
            })
            .into_iter()
            .collect(),
        Pattern::Group(delimiter, pattern) => {
            let Some(TokenTree::Group(group)) = input.get(state.position) else {
                return Vec::new();
            };
            if group.delimiter() != *delimiter {
                return Vec::new();
            }
            let nested = group.stream().into_iter().collect::<Vec<_>>();
            match_sequence(pattern, &nested, 0)
                .into_iter()
                .filter(|matched| matched.position == nested.len())
                .map(|matched| Match {
                    position: state.position + 1,
                    bindings: merge_bindings(state.bindings.clone(), matched.bindings),
                })
                .collect()
        }
        Pattern::Variable { name, kind } => fragment_lengths(kind, input, state.position)
            .into_iter()
            .map(|length| {
                let mut next = state.clone();
                next.bindings
                    .entry(name.clone())
                    .or_default()
                    .push(input[state.position..state.position + length].to_vec());
                next.position += length;
                next
            })
            .collect(),
        Pattern::Repeat {
            body,
            separator,
            minimum,
            maximum,
        } => match_repeat(body, separator, *minimum, *maximum, input, state),
    }
}

fn match_repeat(
    body: &[Pattern],
    separator: &[TokenKey],
    minimum: usize,
    maximum: Option<usize>,
    input: &[TokenTree],
    state: Match,
) -> Vec<Match> {
    let mut accepted = (minimum == 0)
        .then(|| state.clone())
        .into_iter()
        .collect::<Vec<_>>();
    let mut frontier = vec![state];
    for count in 1..=maximum.unwrap_or(input.len() + 1) {
        let mut next = Vec::new();
        for mut current in frontier {
            if count > 1 {
                let matches_separator = separator.iter().enumerate().all(|(offset, expected)| {
                    input
                        .get(current.position + offset)
                        .and_then(token_key)
                        .is_some_and(|token| token == *expected)
                });
                if !matches_separator {
                    continue;
                }
                current.position += separator.len();
            }
            for matched in match_sequence(body, input, current.position) {
                if matched.position > current.position {
                    next.push(Match {
                        position: matched.position,
                        bindings: merge_bindings(current.bindings.clone(), matched.bindings),
                    });
                }
            }
        }
        if count >= minimum {
            accepted.extend(next.iter().cloned());
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    accepted
}

fn merge_bindings(
    mut left: BTreeMap<String, Vec<Vec<TokenTree>>>,
    right: BTreeMap<String, Vec<Vec<TokenTree>>>,
) -> BTreeMap<String, Vec<Vec<TokenTree>>> {
    for (name, values) in right {
        left.entry(name).or_default().extend(values);
    }
    left
}

fn fragment_lengths(kind: &str, input: &[TokenTree], start: usize) -> Vec<usize> {
    let remaining = input.len().saturating_sub(start);
    match kind {
        "ident" if matches!(input.get(start), Some(TokenTree::Ident(_))) => vec![1],
        "tt" if remaining > 0 => vec![1],
        "vis" => (0..=remaining)
            .filter(|length| fragment_is_valid(kind, &input[start..start + length]))
            .collect(),
        _ => (1..=remaining)
            .filter(|length| fragment_is_valid(kind, &input[start..start + length]))
            .collect(),
    }
}

fn tokens_contain_import(tokens: &[TokenTree]) -> bool {
    tokens.iter().any(|token| match token {
        TokenTree::Ident(ident) => {
            !ident.to_string().starts_with("r#") && (ident == "use" || ident == "extern")
        }
        TokenTree::Group(group) => {
            tokens_contain_import(&group.stream().into_iter().collect::<Vec<_>>())
        }
        _ => false,
    })
}

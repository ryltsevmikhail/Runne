use proc_macro2::{TokenStream, TokenTree};

use super::inventory_macro_rules::MacroArm;

#[derive(Clone)]
pub(super) struct MacroArgumentBinding {
    pub(super) name: String,
    pub(super) tokens: TokenStream,
}

#[derive(Clone)]
pub(super) struct ResolvedMacroArm {
    pub(super) matcher: TokenStream,
    pub(super) expansion: TokenStream,
    pub(super) bindings: Vec<MacroArgumentBinding>,
}

pub(super) fn selected_raw_arms(
    arms: &[MacroArm],
    invocation: &TokenStream,
) -> Result<Vec<ResolvedMacroArm>, ()> {
    let invocation_text = invocation.to_string();
    let exact = arms
        .iter()
        .filter(|arm| arm.matcher == invocation_text)
        .collect::<Vec<_>>();
    let selected = if exact.len() == 1 {
        exact
    } else if arms.len() == 1 {
        vec![&arms[0]]
    } else {
        return Err(());
    };
    Ok(selected
        .into_iter()
        .map(|arm| ResolvedMacroArm {
            matcher: arm.matcher_tokens.clone(),
            expansion: arm.expansion_tokens.clone(),
            bindings: argument_bindings(&arm.matcher_tokens, invocation),
        })
        .collect())
}

fn argument_bindings(matcher: &TokenStream, invocation: &TokenStream) -> Vec<MacroArgumentBinding> {
    let tokens = matcher.clone().into_iter().collect::<Vec<_>>();
    let names = matcher_names(&tokens);
    if names.len() == 1 {
        return vec![MacroArgumentBinding {
            name: names[0].clone(),
            tokens: invocation.clone(),
        }];
    }
    let arguments = comma_separated(invocation.clone());
    if names.len() != arguments.len() || !simple_comma_matcher(&tokens, &names) {
        return Vec::new();
    }
    names
        .into_iter()
        .zip(arguments)
        .map(|(name, tokens)| MacroArgumentBinding { name, tokens })
        .collect()
}

fn matcher_names(tokens: &[TokenTree]) -> Vec<String> {
    let mut names = tokens
        .windows(2)
        .filter_map(|pair| match pair {
            [TokenTree::Punct(punct), TokenTree::Ident(name)] if punct.as_char() == '$' => {
                Some(name.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for token in tokens {
        if let TokenTree::Group(group) = token {
            names.extend(matcher_names(
                &group.stream().into_iter().collect::<Vec<_>>(),
            ));
        }
    }
    names
}

fn comma_separated(invocation: TokenStream) -> Vec<TokenStream> {
    let mut arguments = vec![TokenStream::new()];
    for token in invocation {
        if matches!(&token, TokenTree::Punct(punct) if punct.as_char() == ',') {
            arguments.push(TokenStream::new());
        } else {
            arguments.last_mut().expect("argument slot").extend([token]);
        }
    }
    arguments
}

fn simple_comma_matcher(tokens: &[TokenTree], names: &[String]) -> bool {
    let parts =
        tokens.split(|token| matches!(token, TokenTree::Punct(punct) if punct.as_char() == ','));
    let parsed = parts
        .filter_map(|part| match part {
            [
                TokenTree::Punct(dollar),
                TokenTree::Ident(name),
                TokenTree::Punct(colon),
                TokenTree::Ident(_),
            ] if dollar.as_char() == '$' && colon.as_char() == ':' => Some(name.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    parsed == names
}

#[cfg(test)]
mod tests {
    use super::argument_bindings;

    #[test]
    fn binds_two_top_level_expression_arguments() {
        let matcher = "$pending:expr, $release:expr".parse().unwrap();
        let invocation = "pending, release".parse().unwrap();
        let bindings = argument_bindings(&matcher, &invocation);
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].name, "pending");
        assert_eq!(bindings[0].tokens.to_string(), "pending");
        assert_eq!(bindings[1].name, "release");
        assert_eq!(bindings[1].tokens.to_string(), "release");
    }

    #[test]
    fn binds_single_repeated_token_tree_sequence() {
        let matcher = "$($item:tt)*".parse().unwrap();
        let invocation = "mod hidden;".parse().unwrap();
        let bindings = argument_bindings(&matcher, &invocation);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].name, "item");
        assert_eq!(bindings[0].tokens.to_string(), "mod hidden ;");
    }
}

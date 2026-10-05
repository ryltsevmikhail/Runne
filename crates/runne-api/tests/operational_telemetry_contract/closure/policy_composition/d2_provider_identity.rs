use super::super::lexer::Token;

const COMPOSE: &str = "crates/runne-daemon/src/canonical_provider/composition/compose.rs";
const COMPOSITION_INPUT: &str = "crates/runne-daemon/src/canonical_provider/composition/input.rs";

/// Allows the D2 provider identity to be copied into a validated ProviderId
/// before it is used to install the separately granted tool profile.
pub(super) fn is_d2_provider_identity_projection(
    path: &str,
    tokens: &[Token],
    index: usize,
) -> bool {
    path == COMPOSE
        && exact_provider_name_binding(tokens, index)
        && exact_composition_provider_id_destructure(tokens, index)
        && exact_provider_id_validation(tokens, index)
        && count_ident(tokens, "provider_name") == 3
}

/// Pins the projection input to the composition's borrowed provider identifier.
pub(super) fn is_d2_provider_id_input(path: &str, tokens: &[Token]) -> bool {
    if path != COMPOSITION_INPUT {
        return false;
    }
    let Some(struct_index) = tokens.windows(2).position(|pair| {
        matches!(pair, [Token::Ident(kind), Token::Ident(name)] if kind == "struct" && name == "DaemonCanonicalProviderComposition")
    }) else {
        return false;
    };
    let Some(open) = (struct_index + 2..tokens.len()).find(|index| punct(tokens, *index, '{'))
    else {
        return false;
    };
    let Some(close) = matching_brace(tokens, open) else {
        return false;
    };
    tokens[open + 1..close].windows(13).any(|field| {
        matches!(
            field,
            [
                Token::Ident(pub_vis),
                Token::Punct('('),
                Token::Ident(crate_vis),
                Token::Punct(')'),
                Token::Ident(name),
                Token::Punct(':'),
                Token::Ident(cow),
                Token::Punct('<'),
                Token::Punct('\''),
                Token::Ident(static_lifetime),
                Token::Punct(','),
                Token::Ident(str_type),
                Token::Punct('>')
            ] if pub_vis == "pub" && crate_vis == "crate" && name == "provider_id" && cow == "Cow" && static_lifetime == "static" && str_type == "str"
        )
    })
}

fn exact_provider_name_binding(tokens: &[Token], index: usize) -> bool {
    index >= 5
        && ident(tokens, index - 5) == Some("let")
        && ident(tokens, index - 4) == Some("provider_name")
        && punct(tokens, index - 3, '=')
        && ident(tokens, index - 2) == Some("provider_id")
        && punct(tokens, index - 1, '.')
        && ident(tokens, index) == Some("to_string")
        && punct(tokens, index + 1, '(')
        && punct(tokens, index + 2, ')')
        && punct(tokens, index + 3, ';')
}

fn exact_composition_provider_id_destructure(tokens: &[Token], index: usize) -> bool {
    (0..index).any(|struct_index| {
        if ident(tokens, struct_index.wrapping_sub(1)) != Some("let")
            || ident(tokens, struct_index) != Some("DaemonCanonicalProviderComposition")
            || !punct(tokens, struct_index + 1, '{')
        {
            return false;
        }
        let Some(close) = matching_brace(tokens, struct_index + 1) else {
            return false;
        };
        close < index
            && tokens[struct_index + 2..close]
                .windows(2)
                .any(|field| matches!(field, [Token::Ident(name), Token::Punct(',')] if name == "provider_id"))
            && punct(tokens, close + 1, '=')
            && ident(tokens, close + 2) == Some("c")
            && punct(tokens, close + 3, ';')
    })
}

fn exact_provider_id_validation(tokens: &[Token], index: usize) -> bool {
    // Reparse the exact value into the bounded identity type, then pass that
    // typed value and the corresponding label to the D2 grant constructor.
    let start = index + 4;
    let expected = [
        TokenPattern::Ident("let"),
        TokenPattern::Ident("provider_id"),
        TokenPattern::Punct('='),
        TokenPattern::Ident("runne_provider"),
        TokenPattern::Punct(':'),
        TokenPattern::Punct(':'),
        TokenPattern::Ident("ProviderId"),
        TokenPattern::Punct(':'),
        TokenPattern::Punct(':'),
        TokenPattern::Ident("new"),
        TokenPattern::Punct('('),
        TokenPattern::Punct('&'),
        TokenPattern::Ident("provider_name"),
        TokenPattern::Punct(')'),
    ];
    expected
        .iter()
        .enumerate()
        .all(|(offset, token)| token.matches(tokens, start + offset))
        && grant_consumes_provider_identity(tokens, start + expected.len())
}

fn grant_consumes_provider_identity(tokens: &[Token], start: usize) -> bool {
    let Some(call) = (start..tokens.len().saturating_sub(5)).find(|index| {
        ident(tokens, *index) == Some("ProviderSecondaryProfileGrantSpec")
            && punct(tokens, index + 1, ':')
            && punct(tokens, index + 2, ':')
            && ident(tokens, index + 3) == Some("new")
            && punct(tokens, index + 4, '(')
    }) else {
        return false;
    };
    let expected = [
        TokenPattern::Punct('&'),
        TokenPattern::Ident("provider_id"),
        TokenPattern::Punct(','),
        TokenPattern::Ident("tool_profile"),
        TokenPattern::Punct('.'),
        TokenPattern::Ident("profile_id"),
        TokenPattern::Punct('('),
        TokenPattern::Punct(')'),
        TokenPattern::Punct(','),
        TokenPattern::Ident("provider_name"),
        TokenPattern::Punct('.'),
        TokenPattern::Ident("as_str"),
        TokenPattern::Punct('('),
        TokenPattern::Punct(')'),
        TokenPattern::Punct(','),
    ];
    expected
        .iter()
        .enumerate()
        .all(|(offset, token)| token.matches(tokens, call + 5 + offset))
}

enum TokenPattern<'a> {
    Ident(&'a str),
    Punct(char),
}

impl TokenPattern<'_> {
    fn matches(&self, tokens: &[Token], index: usize) -> bool {
        match self {
            Self::Ident(name) => ident(tokens, index) == Some(*name),
            Self::Punct(value) => punct(tokens, index, *value),
        }
    }
}

fn ident(tokens: &[Token], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(Token::Ident(name)) => Some(name),
        _ => None,
    }
}

fn punct(tokens: &[Token], index: usize, expected: char) -> bool {
    matches!(tokens.get(index), Some(Token::Punct(value)) if *value == expected)
}

fn matching_brace(tokens: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token {
            Token::Punct('{') => depth = depth.checked_add(1)?,
            Token::Punct('}') => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn count_ident(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .filter(|token| matches!(token, Token::Ident(value) if value == name))
        .count()
}

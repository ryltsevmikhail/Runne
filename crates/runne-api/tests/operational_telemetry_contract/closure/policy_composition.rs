use super::lexer::Token;

const ENROLLMENT: &str = "crates/runne-daemon/src/application/http_startup/enrollment.rs";
const PROFILE_MODELS: &str = "crates/runne-daemon/src/application/http_startup/profile_models.rs";
const SECONDARY_BACKGROUND: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_background.rs";
const SECONDARY_METADATA: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_effects_metadata.rs";

/// Allows only the provider-ID string in the exact enrollment control list.
pub(super) fn is_exact_enrollment_control_list(path: &str, tokens: &[Token], index: usize) -> bool {
    path == ENROLLMENT
        && index >= 5
        && ident(tokens, index - 5) == Some("credential_enrollment_controls")
        && punct(tokens, index - 4, ':')
        && ident(tokens, index - 3) == Some("Vec")
        && punct(tokens, index - 2, '<')
        && punct(tokens, index - 1, '(')
        && ident(tokens, index) == Some("String")
        && punct(tokens, index + 1, ',')
        && ident(tokens, index + 2) == Some("Arc")
        && punct(tokens, index + 3, '<')
        && ident(tokens, index + 4) == Some("DaemonProviderCredentialEnrollmentControl")
        && punct(tokens, index + 5, '>')
        && punct(tokens, index + 6, ')')
        && punct(tokens, index + 7, '>')
}

pub(super) fn is_selected_profile_model_label(path: &str, tokens: &[Token], index: usize) -> bool {
    path == PROFILE_MODELS
        && index >= 13
        && punct(tokens, index - 13, '-')
        && punct(tokens, index - 12, '>')
        && punct(tokens, index - 11, '(')
        && ident(tokens, index - 10) == Some("Vec")
        && punct(tokens, index - 9, '<')
        && ident(tokens, index - 8) == Some("SelectedProviderProfile")
        && punct(tokens, index - 7, '>')
        && punct(tokens, index - 6, ',')
        && ident(tokens, index - 5) == Some("Vec")
        && punct(tokens, index - 4, '<')
        && punct(tokens, index - 3, '(')
        && ident(tokens, index - 2) == Some("SelectedProviderProfile")
        && punct(tokens, index - 1, ',')
        && ident(tokens, index) == Some("String")
        && punct(tokens, index + 1, ')')
        && punct(tokens, index + 2, '>')
        && (punct(tokens, index + 3, ')')
            || (punct(tokens, index + 3, ',') && punct(tokens, index + 4, ')')))
        && has_selected_profile_models_signature(tokens, index)
}

pub(super) fn is_secondary_background_db_path(path: &str, tokens: &[Token], index: usize) -> bool {
    if path != SECONDARY_BACKGROUND
        || index < 6
        || ident(tokens, index - 6) != Some("pub")
        || !punct(tokens, index - 5, '(')
        || ident(tokens, index - 4) != Some("super")
        || !punct(tokens, index - 3, ')')
        || ident(tokens, index - 2) != Some("db_path")
        || !punct(tokens, index - 1, ':')
    {
        return false;
    }
    let Some(struct_start) = tokens[..index]
        .windows(2)
        .rposition(|pair| matches!(pair, [Token::Ident(kind), Token::Ident(name)] if kind == "struct" && name == "SecondaryBackgroundConfig"))
    else {
        return false;
    };
    let Some(open) = tokens[struct_start + 2..index]
        .iter()
        .position(|token| matches!(token, Token::Punct('{')))
        .map(|offset| struct_start + 2 + offset)
    else {
        return false;
    };
    !tokens[open + 1..index]
        .iter()
        .any(|token| matches!(token, Token::Punct('}')))
}

pub(super) fn is_secondary_metadata_string(path: &str, tokens: &[Token], index: usize) -> bool {
    if path != SECONDARY_METADATA
        || index < 3
        || !matches!(
            ident(tokens, index - 2),
            Some("provider_id" | "credential_realm" | "profile_id" | "db_path")
        )
        || !punct(tokens, index - 1, ':')
        || !punct(tokens, index + 1, ',')
        || !(punct(tokens, index - 3, ',') || punct(tokens, index - 3, '{'))
    {
        return false;
    }
    let Some(struct_start) = tokens[..index]
        .windows(2)
        .rposition(|pair| matches!(pair, [Token::Ident(kind), Token::Ident(name)] if kind == "struct" && name == "SecondaryEffectsMetadata"))
    else {
        return false;
    };
    let Some(open) = tokens[struct_start + 2..index]
        .iter()
        .position(|token| matches!(token, Token::Punct('{')))
        .map(|offset| struct_start + 2 + offset)
    else {
        return false;
    };
    !tokens[open + 1..index]
        .iter()
        .any(|token| matches!(token, Token::Punct('}')))
}

fn has_selected_profile_models_signature(tokens: &[Token], index: usize) -> bool {
    let Some(function) = tokens[..index]
        .windows(2)
        .rposition(|pair| matches!(pair, [Token::Ident(name), Token::Ident(function)] if name == "fn" && function == "selected_profile_models"))
    else {
        return false;
    };
    tokens[function + 2..index]
        .iter()
        .all(|token| !matches!(token, Token::Punct('{')))
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

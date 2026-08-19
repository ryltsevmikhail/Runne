use super::lexer::Token;

const RUNTIME_CLIENT: &str = "crates/runne-runtime-client/src/canonical/operational_telemetry.rs";
const OPERATIONAL_TELEMETRY_PATH: &str = "OPERATIONAL_TELEMETRY_PATH";

pub(super) fn audit_tokens(path: &str, tokens: &[Token]) -> Result<(), String> {
    audit_reqwest(path, tokens)?;
    if path != RUNTIME_CLIENT {
        return Ok(());
    }
    for (index, token) in tokens.iter().enumerate() {
        let Some(name) = ident(token) else {
            continue;
        };
        if is_method(tokens, index)
            && matches!(
                name,
                "post"
                    | "put"
                    | "patch"
                    | "delete"
                    | "head"
                    | "request"
                    | "build"
                    | "execute"
                    | "connect"
                    | "bytes"
                    | "text"
                    | "json"
            )
        {
            return reject(index, "unapproved HTTP request or response method");
        }
        if is_response_method(tokens, index) && !matches!(name, "status" | "headers" | "chunk") {
            return reject(index, "unapproved response operation");
        }
    }
    if has_exact_client_chain(tokens)
        && has_exact_client_counts(tokens)
        && has_bounded_chunk_reader(tokens)
    {
        Ok(())
    } else {
        Err(
            "runne-runtime-client must retain one bounded authenticated telemetry GET chain"
                .to_owned(),
        )
    }
}

pub(super) fn allowed_reqwest(path: &str, tokens: &[Token], index: usize) -> bool {
    path == RUNTIME_CLIENT
        && punct(tokens, index + 1, ':')
        && punct(tokens, index + 2, ':')
        && matches!(
            ident_at(tokens, index + 3),
            Some("Response" | "Error" | "StatusCode" | "header")
        )
}

pub(super) fn allows_authenticated_send(path: &str, tokens: &[Token]) -> bool {
    path == RUNTIME_CLIENT && has_exact_client_chain(tokens) && has_exact_client_counts(tokens)
}

fn audit_reqwest(path: &str, tokens: &[Token]) -> Result<(), String> {
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, Token::Ident(name) if name == "reqwest")
            && !allowed_reqwest(path, tokens, index)
        {
            return reject(index, "outbound network client");
        }
    }
    Ok(())
}

fn has_exact_client_chain(tokens: &[Token]) -> bool {
    (0..tokens.len()).any(|index| {
        ident_at(tokens, index) == Some("self")
            && punct(tokens, index + 1, '.')
            && ident_at(tokens, index + 2) == Some("authenticated_request")
            && punct(tokens, index + 3, '(')
            && ident_at(tokens, index + 4) == Some("self")
            && punct(tokens, index + 5, '.')
            && ident_at(tokens, index + 6) == Some("http_client")
            && punct(tokens, index + 7, '(')
            && punct(tokens, index + 8, ')')
            && punct(tokens, index + 9, '.')
            && ident_at(tokens, index + 10) == Some("get")
            && punct(tokens, index + 11, '(')
            && ident_at(tokens, index + 12) == Some("self")
            && punct(tokens, index + 13, '.')
            && ident_at(tokens, index + 14) == Some("url")
            && punct(tokens, index + 15, '(')
            && ident_at(tokens, index + 16) == Some(OPERATIONAL_TELEMETRY_PATH)
            && punct(tokens, index + 17, ')')
            && punct(tokens, index + 18, ')')
            && punct(tokens, index + 19, ')')
            && punct(tokens, index + 20, '?')
            && punct(tokens, index + 21, '.')
            && ident_at(tokens, index + 22) == Some("send")
            && punct(tokens, index + 23, '(')
            && punct(tokens, index + 24, ')')
    })
}

fn has_exact_client_counts(tokens: &[Token]) -> bool {
    count(tokens, "authenticated_request") == 1
        && count(tokens, "http_client") == 1
        && count(tokens, "get") == 1
        && count(tokens, "send") == 1
        && count(tokens, "url") == 1
        && count(tokens, OPERATIONAL_TELEMETRY_PATH) == 2
}

fn has_bounded_chunk_reader(tokens: &[Token]) -> bool {
    count_response_method(tokens, "status") >= 1
        && count_response_method(tokens, "headers") >= 1
        && count_response_method(tokens, "chunk") == 1
        && has_chunk_loop(tokens)
        && count(tokens, "checked_add") == 1
        && count(tokens, "extend_from_slice") == 1
}

fn has_chunk_loop(tokens: &[Token]) -> bool {
    (0..tokens.len()).any(|index| {
        ident_at(tokens, index) == Some("while")
            && ident_at(tokens, index + 1) == Some("let")
            && ident_at(tokens, index + 2) == Some("Some")
            && punct(tokens, index + 3, '(')
            && ident_at(tokens, index + 4) == Some("chunk")
            && punct(tokens, index + 5, ')')
            && punct(tokens, index + 6, '=')
            && ident_at(tokens, index + 7) == Some("response")
            && punct(tokens, index + 8, '.')
            && ident_at(tokens, index + 9) == Some("chunk")
    })
}

fn count_response_method(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| ident(token) == Some(name) && is_response_method(tokens, *index))
        .count()
}

fn count(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .filter(|token| ident(token) == Some(name))
        .count()
}

fn is_method(tokens: &[Token], index: usize) -> bool {
    punct(tokens, index.wrapping_sub(1), '.')
}

fn is_response_method(tokens: &[Token], index: usize) -> bool {
    is_method(tokens, index) && ident_at(tokens, index.wrapping_sub(2)) == Some("response")
}

fn ident(token: &Token) -> Option<&str> {
    match token {
        Token::Ident(name) => Some(name),
        _ => None,
    }
}

fn ident_at(tokens: &[Token], index: usize) -> Option<&str> {
    tokens.get(index).and_then(ident)
}

fn punct(tokens: &[Token], index: usize, expected: char) -> bool {
    matches!(tokens.get(index), Some(Token::Punct(value)) if *value == expected)
}

fn reject(index: usize, what: &str) -> Result<(), String> {
    Err(format!("token {index}: {what}"))
}

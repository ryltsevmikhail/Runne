use super::lexer::Token;

pub(super) fn in_attribute(tokens: &[Token], index: usize) -> bool {
    for index in (0..index).rev() {
        match &tokens[index] {
            Token::Punct(']') | Token::Punct(';') | Token::Punct('{') | Token::Punct('}') => {
                return false;
            }
            Token::Punct('[') => {
                return index > 0
                    && (punct(tokens, index - 1, '#')
                        || (index > 1
                            && punct(tokens, index - 2, '#')
                            && punct(tokens, index - 1, '!')));
            }
            _ => {}
        }
    }
    false
}

pub(super) fn is_forbidden_ffi_identifier(name: &str) -> bool {
    matches!(name, "libc" | "unsafe" | "extern")
}

pub(super) fn is_std_or_tokio_module(tokens: &[Token], index: usize) -> bool {
    matches!(ident(tokens, index.wrapping_sub(3)), Some("std" | "tokio"))
        && punct(tokens, index.wrapping_sub(2), ':')
        && punct(tokens, index.wrapping_sub(1), ':')
        && punct(tokens, index + 1, ':')
        && punct(tokens, index + 2, ':')
}

pub(super) fn is_appcore_operational_rwlock_write(
    path: &str,
    tokens: &[Token],
    index: usize,
) -> bool {
    path == "crates/runne-app-core/src/lib_parts/operational_telemetry_state.rs"
        && index >= 4
        && matches!(tokens.get(index - 4), Some(Token::Ident(name)) if name == "self")
        && punct(tokens, index - 3, '.')
        && matches!(tokens.get(index - 2), Some(Token::Ident(name)) if name == "host_lifecycle")
        && punct(tokens, index - 1, '.')
        && punct(tokens, index + 1, '(')
        && tokens
            .iter()
            .enumerate()
            .filter(|(position, token)| {
                matches!(token, Token::Ident(name) if name == "write")
                    && punct(tokens, position.wrapping_sub(1), '.')
                    && punct(tokens, position + 1, '(')
            })
            .count()
            == 1
}

pub(super) fn is_allowed_control_sink(
    path: &str,
    tokens: &[Token],
    index: usize,
    name: &str,
) -> bool {
    is_appcore_operational_rwlock_write(path, tokens, index)
        || matches!(
            (path, name, prior_ident(tokens, index)),
            (
                "crates/runne-http/src/secure_local_host.rs",
                "send",
                Some("stop")
            ) | (
                "crates/runne-daemon/src/application/http_startup.rs",
                "shutdown",
                Some("runtime_controller")
            ) | (
                "crates/runne-daemon/src/application/shutdown.rs",
                "shutdown",
                Some("controller")
            )
        ) && direct_method_count(tokens, name) == 1
}

fn prior_ident(tokens: &[Token], index: usize) -> Option<&str> {
    match tokens.get(index.wrapping_sub(2)) {
        Some(Token::Ident(name)) => Some(name),
        _ => None,
    }
}

fn ident(tokens: &[Token], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(Token::Ident(name)) => Some(name),
        _ => None,
    }
}

fn direct_method_count(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .enumerate()
        .filter(|(index, token)| {
            matches!(token, Token::Ident(value) if value == name)
                && punct(tokens, index.wrapping_sub(1), '.')
                && punct(tokens, index + 1, '(')
        })
        .count()
}

fn punct(tokens: &[Token], index: usize, expected: char) -> bool {
    matches!(tokens.get(index), Some(Token::Punct(value)) if *value == expected)
}

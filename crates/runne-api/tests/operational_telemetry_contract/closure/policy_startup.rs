use super::lexer::Token;

const START: &str = "crates/runne-daemon/src/application/http_startup/start.rs";

pub(super) fn is_known_runtime_shutdown(
    path: &str,
    tokens: &[Token],
    index: usize,
    name: &str,
) -> bool {
    path == START
        && name == "shutdown"
        && index >= 2
        && ident(tokens, index - 2) == Some("runtime_controller")
        && punct(tokens, index - 1, '.')
        && punct(tokens, index + 1, '(')
        && ident(tokens, index + 2) == Some("ShutdownMode")
        && punct(tokens, index + 3, ':')
        && punct(tokens, index + 4, ':')
        && ident(tokens, index + 5) == Some("Immediate")
        && punct(tokens, index + 6, '{')
        && ident(tokens, index + 7) == Some("timeout")
        && punct(tokens, index + 8, ':')
        && ident(tokens, index + 9) == Some("shutdown_timeout")
        && known_shutdown_tail(tokens, index)
}

fn known_shutdown_tail(tokens: &[Token], index: usize) -> bool {
    let close_brace = if punct(tokens, index + 10, ',') {
        index + 11
    } else {
        index + 10
    };
    if !punct(tokens, close_brace, '}') {
        return false;
    }
    let close_call = if punct(tokens, close_brace + 1, ',') {
        close_brace + 2
    } else {
        close_brace + 1
    };
    punct(tokens, close_call, ')')
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

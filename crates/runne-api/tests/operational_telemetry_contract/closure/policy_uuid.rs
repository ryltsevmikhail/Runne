use super::lexer::Token;

const AUTOMATIC_TASKRUNS: &str =
    "crates/runne-daemon/src/application/http_startup/automatic_taskruns.rs";
const HTTP_STARTUP: &str = "crates/runne-daemon/src/application/http_startup.rs";
const COMPOSITION: &str = "crates/runne-daemon/src/canonical_provider/composition.rs";
const START: &str = "crates/runne-daemon/src/application/http_startup/start.rs";
const REPLAY_SETUP: &str = "crates/runne-daemon/src/application/http_startup/replay_setup.rs";
const JOURNAL_BOOTSTRAP: &str =
    "crates/runne-daemon/src/canonical_provider/composition/journal_bootstrap.rs";

pub(super) fn is_allowed_to_string_projection(path: &str, tokens: &[Token], index: usize) -> bool {
    is_daemon_error_wrapper(path, tokens, index)
        || is_exact_authority_uuid_format(path, tokens, index)
}

fn is_daemon_error_wrapper(path: &str, tokens: &[Token], index: usize) -> bool {
    (matches!(path, HTTP_STARTUP | COMPOSITION | START | REPLAY_SETUP)
        || (path == JOURNAL_BOOTSTRAP && ident(tokens, index.wrapping_sub(4)) == Some("Bootstrap")))
        && index >= 7
        && ident(tokens, index - 7) == Some("DaemonError")
        && punct(tokens, index - 6, ':')
        && punct(tokens, index - 5, ':')
        && matches!(ident(tokens, index - 4), Some("Config" | "Bootstrap"))
        && punct(tokens, index - 3, '(')
        && ident(tokens, index - 2) == Some("error")
        && punct(tokens, index - 1, '.')
        && punct(tokens, index + 1, '(')
        && punct(tokens, index + 2, ')')
        && punct(tokens, index + 3, ')')
}

/// Allows only formatting the exact UUID authority value needed by the worker.
fn is_exact_authority_uuid_format(path: &str, tokens: &[Token], index: usize) -> bool {
    path == AUTOMATIC_TASKRUNS
        && index >= 11
        && ident(tokens, index - 11) == Some("uuid")
        && punct(tokens, index - 10, ':')
        && punct(tokens, index - 9, ':')
        && ident(tokens, index - 8) == Some("Uuid")
        && punct(tokens, index - 7, ':')
        && punct(tokens, index - 6, ':')
        && ident(tokens, index - 5) == Some("from_bytes")
        && punct(tokens, index - 4, '(')
        && ident(tokens, index - 3) == Some("authority_id")
        && punct(tokens, index - 2, ')')
        && punct(tokens, index - 1, '.')
        && ident(tokens, index) == Some("to_string")
        && punct(tokens, index + 1, '(')
        && punct(tokens, index + 2, ')')
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

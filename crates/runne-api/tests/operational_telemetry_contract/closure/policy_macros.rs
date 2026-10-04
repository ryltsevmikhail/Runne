use super::lexer::{StringKind, Token};

const HTTP_HOST: &str = "crates/runne-http/src/secure_local_host.rs";
const START: &str = "crates/runne-daemon/src/application/http_startup/start.rs";
const REPLAY_SETUP: &str = "crates/runne-daemon/src/application/http_startup/replay_setup.rs";
const COMPOSITION: &str = "crates/runne-daemon/src/canonical_provider/composition.rs";
const OBSERVABILITY: &str = "crates/runne-observability/src/operational.rs";
const AGGREGATES: &str = "crates/runne-store/src/provider/operational_telemetry/aggregates.rs";
const ACCOUNTING: &str = "crates/runne-store/src/provider/operational_telemetry/accounting.rs";
const RUNTIME: &str = "crates/runne-store/src/provider/operational_telemetry/runtime.rs";
const MODEL_PIN: &str = "crates/runne-daemon/src/canonical_provider/composition/model_pin.rs";
const SECONDARY_BACKGROUND: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_background.rs";
const SECONDARY_METADATA: &str =
    "crates/runne-daemon/src/canonical_provider/composition/secondary_effects_metadata.rs";

pub(super) fn audit(
    path: &str,
    tokens: &[Token],
    index: usize,
    name: Vec<&str>,
    open: usize,
    known_item_include: bool,
) -> Result<(), String> {
    let last = name.last().copied().unwrap_or_default();
    if matches!(
        last,
        "macro_rules" | "include_str" | "option_env" | "println" | "eprintln" | "dbg"
    ) || (last == "include" && !known_item_include)
    {
        return reject(index, "forbidden macro");
    }
    let allowed = match name.as_slice() {
        ["include"] => path == COMPOSITION && known_item_include,
        ["matches"] => true,
        ["unreachable"] => path == OBSERVABILITY && empty_group(tokens, open),
        ["vec"] => path == AGGREGATES || exact_selected_identity_vec(path, tokens, open),
        ["params"] => path == ACCOUNTING || path == RUNTIME,
        ["tokio", "pin"] | ["tokio", "select"] => path == HTTP_HOST,
        ["format"] => existing_format(path, tokens, index, open),
        ["env"] => path == START && cargo_pkg_version(tokens, index, open),
        ["include_bytes"] => {
            (path == COMPOSITION && openai_profile(tokens, open))
                || exact_background_profile(path, tokens, open)
        }
        _ => false,
    };
    allowed
        .then_some(())
        .ok_or_else(|| format!("token {index}: unaudited macro `{}`", name.join("::")))
}

pub(super) fn is_allowed_env(tokens: &[Token], index: usize) -> bool {
    macro_at(tokens, index).is_some_and(|(name, _)| name.as_slice() == ["env"])
}

pub(super) fn macro_at(tokens: &[Token], index: usize) -> Option<(Vec<&str>, usize)> {
    if index >= 2 && punct(tokens, index - 2, ':') && punct(tokens, index - 1, ':') {
        return None;
    }
    let mut names = vec![ident(tokens, index)?];
    let mut next = index + 1;
    while punct(tokens, next, ':') && punct(tokens, next + 1, ':') {
        names.push(ident(tokens, next + 2)?);
        next += 3;
    }
    (punct(tokens, next, '!')
        && matches!(tokens.get(next + 1), Some(Token::Punct('(' | '[' | '{'))))
    .then_some((names, next + 1))
}

fn existing_format(path: &str, tokens: &[Token], index: usize, open: usize) -> bool {
    let message = match (path, tokens.get(open + 1)) {
        (
            START,
            Some(Token::String {
                value,
                kind: StringKind::Ordinary,
            }),
        ) if matches!(
            value.as_str(),
            "start runtime: {error}" | "configure replay transport: {error}"
        ) =>
        {
            value
        }
        (
            REPLAY_SETUP,
            Some(Token::String {
                value,
                kind: StringKind::Ordinary,
            }),
        ) if value == "measure retained replay inventory: {error}" => value,
        _ => return false,
    };
    let _ = message;
    index >= 5
        && ident(tokens, index - 5) == Some("DaemonError")
        && punct(tokens, index - 4, ':')
        && punct(tokens, index - 3, ':')
        && ident(tokens, index - 2) == Some("Bootstrap")
        && punct(tokens, index - 1, '(')
        && punct(tokens, open + 2, ')')
        && punct(tokens, open + 3, ')')
}

fn cargo_pkg_version(tokens: &[Token], index: usize, open: usize) -> bool {
    matches!(tokens.get(open + 1), Some(Token::String { value, kind: StringKind::Ordinary }) if value == "CARGO_PKG_VERSION")
        && punct(tokens, open + 2, ')')
        && index >= 5
        && ident(tokens, index - 5) == Some("profile")
        && punct(tokens, index - 4, ':')
        && punct(tokens, index - 3, ':')
        && ident(tokens, index - 2) == Some("runtime_profile")
        && punct(tokens, index - 1, '(')
}

fn openai_profile(tokens: &[Token], open: usize) -> bool {
    matches!(tokens.get(open + 1), Some(Token::String { value, kind: StringKind::Ordinary }) if value == "../../../../docs/profiles/openai-responses-text-v1.json")
}

fn exact_selected_identity_vec(path: &str, tokens: &[Token], open: usize) -> bool {
    path == MODEL_PIN
        && ident(tokens, open + 1) == Some("self")
        && punct(tokens, open + 2, '.')
        && ident(tokens, open + 3) == Some("selected_profile_identity")
        && punct(tokens, open + 4, '(')
        && punct(tokens, open + 5, ')')
        && punct(tokens, open + 6, ']')
}

fn exact_background_profile(path: &str, tokens: &[Token], open: usize) -> bool {
    matches!(path, SECONDARY_BACKGROUND | SECONDARY_METADATA)
        && matches!(
            tokens.get(open + 1),
            Some(Token::String {
                value,
                kind: StringKind::Ordinary
            }) if value == "../../../../../docs/profiles/openai-responses-background-text-v1.json"
        )
        && punct(tokens, open + 2, ')')
}

fn empty_group(tokens: &[Token], open: usize) -> bool {
    matches!(
        tokens.get(open + 1),
        Some(Token::Punct(')')) | Some(Token::Punct(']')) | Some(Token::Punct('}'))
    )
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

fn reject(index: usize, what: &str) -> Result<(), String> {
    Err(format!("token {index}: {what}"))
}

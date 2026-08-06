use super::lexer::Token;

const HTTP_HOST: &str = "crates/gocode-http/src/secure_local_host.rs";
const HTTP_STARTUP: &str = "crates/gocode-daemon/src/application/http_startup.rs";
const COMPOSITION: &str = "crates/gocode-daemon/src/canonical_provider/composition.rs";
const OBSERVABILITY: &str = "crates/gocode-observability/src/operational.rs";
const AGGREGATES: &str = "crates/gocode-store/src/provider/operational_telemetry/aggregates.rs";
const ACCOUNTING: &str = "crates/gocode-store/src/provider/operational_telemetry/accounting.rs";
const RUNTIME: &str = "crates/gocode-store/src/provider/operational_telemetry/runtime.rs";

pub(super) fn audit(
    path: &str,
    tokens: &[Token],
    index: usize,
    name: Vec<&str>,
    open: usize,
) -> Result<(), String> {
    let last = name.last().copied().unwrap_or_default();
    if matches!(
        last,
        "include" | "macro_rules" | "include_str" | "option_env" | "println" | "eprintln" | "dbg"
    ) {
        return reject(index, "forbidden macro");
    }
    let allowed = match name.as_slice() {
        ["matches"] => true,
        ["unreachable"] => path == OBSERVABILITY && empty_group(tokens, open),
        ["vec"] => path == AGGREGATES,
        ["params"] => path == ACCOUNTING || path == RUNTIME,
        ["tokio", "pin"] | ["tokio", "select"] => path == HTTP_HOST,
        ["format"] => path == HTTP_STARTUP && existing_format(tokens, open),
        ["env"] => path == HTTP_STARTUP && cargo_pkg_version(tokens, open),
        ["include_bytes"] => path == COMPOSITION && openai_profile(tokens, open),
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

fn existing_format(tokens: &[Token], open: usize) -> bool {
    matches!(tokens.get(open + 1), Some(Token::String { value, .. }) if matches!(value.as_str(), "start runtime: {error}" | "configure replay transport: {error}" | "measure retained replay inventory: {error}"))
}

fn cargo_pkg_version(tokens: &[Token], open: usize) -> bool {
    matches!(tokens.get(open + 1), Some(Token::String { value, .. }) if value == "CARGO_PKG_VERSION")
}

fn openai_profile(tokens: &[Token], open: usize) -> bool {
    matches!(tokens.get(open + 1), Some(Token::String { value, .. }) if value == "../../../../docs/profiles/openai-responses-text-v1.json")
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

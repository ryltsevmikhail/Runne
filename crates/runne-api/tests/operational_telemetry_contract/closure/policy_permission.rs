use super::lexer::Token;

const PERMISSION_PROJECTION: &str =
    "crates/runne-daemon/src/application/http_startup/command_hosts/permission_projection.rs";

/// The exact `Error::…` payloads of the mapper's `Command(...)` arms.
const COMMAND_PAYLOAD_VARIANTS: [&str; 9] = [
    "ReauthenticationRequired",
    "StaleRevision",
    "IdempotencyConflict",
    "PolicyDenied",
    "Expired",
    "Cancelled",
    "ReconciliationRequired",
    "CompositePolicyUnenforceable",
    "UnsupportedPresetVersion",
];

/// Owner-approved exact enum exemption for the process-access heuristic:
/// the only `Command` token accepted in the closure is the enum
/// MATCH-PATTERN label `PermissionModeStoreError::Command(payload)` inside
/// the permission-projection mapper, with the actual pattern continuation
/// (`=>` or an or-pattern `|`), while the file binds the current
/// `runne_store` enum through its actual `use runne_store::store::{...}`
/// import and nothing aliases the enum name. The exclusion covers exactly
/// this one identifier token: enclosing branches, payloads, and all other
/// tokens stay audited. Token-level shape only — no AST or name-resolution
/// proof is claimed beyond the implemented parser.
pub(super) fn is_store_command_variant(path: &str, tokens: &[Token], index: usize) -> bool {
    path == PERMISSION_PROJECTION
        && is_exact_variant_pattern(tokens, index)
        && binds_store_error_import(tokens)
        && !aliases_store_error_name(tokens)
}

/// `PermissionModeStoreError :: Command ( payload ) =>` (or `... ) |`).
/// The qualifier starts the path — a foreign `foo::`-style prefix is
/// rejected — and the right boundary requires the actual pattern
/// continuation, so constructor (`Command::new`), type, and import
/// positions of the qualified path are never accepted.
fn is_exact_variant_pattern(tokens: &[Token], index: usize) -> bool {
    if index < 3
        || ident(tokens, index - 3) != Some("PermissionModeStoreError")
        || !punct(tokens, index - 2, ':')
        || !punct(tokens, index - 1, ':')
        || (index >= 5 && punct(tokens, index - 5, ':') && punct(tokens, index - 4, ':'))
    {
        return false;
    }
    let Some(close) = pattern_payload_close(tokens, index) else {
        return false;
    };
    (punct(tokens, close + 1, '=') && punct(tokens, close + 2, '>'))
        || punct(tokens, close + 1, '|')
}

/// `(` `_` `)` or `(` `Error :: <exact mapped variant>` `)`.
fn pattern_payload_close(tokens: &[Token], index: usize) -> Option<usize> {
    if punct(tokens, index + 1, '(')
        && ident(tokens, index + 2) == Some("_")
        && punct(tokens, index + 3, ')')
    {
        return Some(index + 3);
    }
    let variant = ident(tokens, index + 5)?;
    (punct(tokens, index + 1, '(')
        && ident(tokens, index + 2) == Some("Error")
        && punct(tokens, index + 3, ':')
        && punct(tokens, index + 4, ':')
        && COMMAND_PAYLOAD_VARIANTS.contains(&variant)
        && punct(tokens, index + 6, ')'))
    .then_some(index + 6)
}

/// The actual fully-qualified import binding of the current `runne_store`
/// enum: a direct first-level whole-symbol `PermissionModeStoreError` entry
/// — preceded by `{` or `,` and followed by `,` or `}` — inside the FIRST
/// `use runne_store::store::{...}` group. The scan stops exactly at that
/// group's closing brace: no spillover into later imports, no nested
/// groups, no alias targets, and fail-closed on malformed imports.
fn binds_store_error_import(tokens: &[Token]) -> bool {
    let Some(open) = store_import_open(tokens) else {
        return false;
    };
    let mut index = open + 1;
    while let Some(token) = tokens.get(index) {
        match token {
            Token::Punct('{') => return false,
            Token::Punct('}') => return false,
            Token::Punct(',') | Token::Punct(';') => {}
            Token::Ident(name) if name == "PermissionModeStoreError" => {
                return (punct(tokens, index - 1, '{') || punct(tokens, index - 1, ','))
                    && matches!(
                        tokens.get(index + 1),
                        Some(Token::Punct(',')) | Some(Token::Punct('}'))
                    );
            }
            _ => {}
        }
        index += 1;
    }
    false
}

/// The index of the `{` of the first `use runne_store::store::{` group.
fn store_import_open(tokens: &[Token]) -> Option<usize> {
    (0..tokens.len())
        .filter(|&start| {
            ident(tokens, start) == Some("use")
                && ident(tokens, start + 1) == Some("runne_store")
                && punct(tokens, start + 2, ':')
                && punct(tokens, start + 3, ':')
                && ident(tokens, start + 4) == Some("store")
                && punct(tokens, start + 5, ':')
                && punct(tokens, start + 6, ':')
                && punct(tokens, start + 7, '{')
        })
        .map(|start| start + 7)
        .next()
}

/// A local `use ... as PermissionModeStoreError` (e.g. the grouped
/// `use std::{process as PermissionModeStoreError}`) legally shadows the
/// enum import in Rust; any such alias binding disables the allowance.
fn aliases_store_error_name(tokens: &[Token]) -> bool {
    (0..tokens.len()).any(|index| {
        ident(tokens, index) == Some("as")
            && ident(tokens, index + 1) == Some("PermissionModeStoreError")
    })
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

use super::policy_helpers;
use super::{
    lexer::Token, policy_composition, policy_helpers::in_attribute, policy_macros,
    policy_permission, policy_runtime_client, policy_startup, policy_uuid,
};

const RUNTIME_CLIENT: &str = "crates/runne-runtime-client/src/canonical/operational_telemetry.rs";
const HTTP_HOST: &str = "crates/runne-http/src/secure_local_host.rs";
const HTTP_TELEMETRY: &str = "crates/runne-http/src/operational_telemetry.rs";
const COMPOSITION: &str = "crates/runne-daemon/src/canonical_provider/composition.rs";
const COMPOSITION_INPUT: &str = "crates/runne-daemon/src/canonical_provider/composition/input.rs";
const AGGREGATES: &str = "crates/runne-store/src/provider/operational_telemetry/aggregates.rs";
const PART_01: &str = "crates/runne-runtime/src/provider_execution_parts/part_01.rs";
// Tool activity is a bounded, content-scanned API projection, not
// operational telemetry; its display strings are intentionally dynamic.
const TOOL_ACTIVITY: &str =
    "crates/runne-daemon/src/application/http_startup/tool_activity.rs";

const SECURE_HOSTS: &[&str] = &[
    HTTP_HOST,
    "crates/runne-http/src/secure_local_host/operational_telemetry.rs",
    "crates/runne-http/src/secure_local_host/project_workspace.rs",
];

pub(super) fn audit_tokens(path: &str, tokens: &[Token]) -> Result<(), String> {
    // Delivery status is a closed-code diagnostic side channel, not telemetry:
    // it writes only a fixed stage name and never accepts external text.
    if path == "crates/runne-daemon/src/canonical_provider/composition/delivery_status.rs" {
        return Ok(());
    }
    let production = super::parser::production_tokens(tokens)?;
    let includes = super::parser::item_includes(path, &production)?;
    audit_attributes(&production)?;
    for index in 0..production.len() {
        audit_identifier(path, &production, index)?;
        if let Some((name, open)) = policy_macros::macro_at(&production, index) {
            let is_known_include = includes.iter().any(|include| include.token_index == index);
            policy_macros::audit(path, &production, index, name, open, is_known_include)?;
        }
    }
    policy_runtime_client::audit_tokens(path, &production)
}

fn audit_identifier(path: &str, tokens: &[Token], index: usize) -> Result<(), String> {
    let Some(name) = ident(tokens, index) else {
        return Ok(());
    };
    if name.to_ascii_lowercase().contains("exporter")
        || matches!(name, "HashMap" | "BTreeMap" | "IndexMap")
    {
        return reject(index, "exporter identifier or map type");
    }
    if policy_helpers::is_forbidden_ffi_identifier(name)
        || matches!(
            name,
            "anyhow" | "eyre" | "Report" | "tracing" | "log" | "opentelemetry" | "prometheus"
        )
    {
        return reject(index, "dynamic error, logging, or metrics identifier");
    }
    if (name == "env" && !policy_macros::is_allowed_env(tokens, index))
        || (name == "serde_json" && !is_allowed_serde_json(path, tokens, index))
        || (name == "Value" && !is_rusqlite_value(path, tokens, index))
        || (name == "String"
            && !is_legacy_string(path, tokens, index)
            && !policy_composition::is_exact_enrollment_control_list(path, tokens, index)
            && !policy_composition::is_selected_profile_model_label(path, tokens, index)
            && !policy_composition::is_secondary_background_db_path(path, tokens, index)
            && !policy_composition::is_secondary_metadata_string(path, tokens, index))
    {
        return reject(index, "unaudited dynamic value");
    }
    if (name == "Box" && follows_dyn_error(tokens, index))
        || (name == "to_string"
            && !policy_uuid::is_allowed_to_string_projection(path, tokens, index)
            && !policy_composition::is_d2_provider_identity_projection(path, tokens, index))
        || (name == "macro_rules" && punct(tokens, index + 1, '!'))
    {
        return reject(index, "dynamic error projection or forbidden macro");
    }
    audit_io_identifier(path, tokens, index, name)
}

fn audit_io_identifier(
    path: &str,
    tokens: &[Token],
    index: usize,
    name: &str,
) -> Result<(), String> {
    if matches!(
        name,
        "TcpSocket"
            | "TcpStream"
            | "UdpSocket"
            | "UnixStream"
            | "Client"
            | "ClientBuilder"
            | "RequestBuilder"
            | "AsyncReadExt"
            | "AsyncWriteExt"
    ) {
        return reject(index, "outbound network client");
    }
    if name == "TcpListener" && !is_tcp_listener(path, tokens, index) {
        return reject(index, "unaudited TCP listener");
    }
    if name == "Command" && !policy_permission::is_store_command_variant(path, tokens, index) {
        return reject(index, "filesystem, standard stream, or process access");
    }
    if matches!(
        name,
        "fs" | "File"
            | "OpenOptions"
            | "stdout"
            | "stderr"
            | "stdin"
            | "BufWriter"
            | "BufReader"
            | "Stdio"
    ) {
        return reject(index, "filesystem, standard stream, or process access");
    }
    if name == "Write" && !is_exact_core_fmt_write(path, tokens, index) {
        return reject(index, "unaudited formatting writer");
    }
    if is_direct_sink(tokens, index, name) && !is_allowed_direct_sink(path, tokens, index, name) {
        return reject(index, "outbound I/O sink");
    }
    if matches!(name, "net" | "io" | "fs" | "process")
        && policy_helpers::is_std_or_tokio_module(tokens, index)
        && !is_allowed_module_path(path, tokens, index, name)
    {
        return reject(index, "unaudited std/tokio I/O module");
    }
    if matches!(name, "hyper" | "hyper_util" | "tokio_rustls")
        && !is_allowed_host_import(path, tokens, index, name)
    {
        return reject(index, "unaudited secure-host dependency");
    }
    Ok(())
}

fn audit_attributes(tokens: &[Token]) -> Result<(), String> {
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, Token::Ident(name) if matches!(name.as_str(), "export_name" | "link_section" | "no_mangle" | "used"))
            && in_attribute(tokens, index)
        {
            return reject(index, "risky export attribute");
        }
    }
    Ok(())
}

fn is_tcp_listener(path: &str, tokens: &[Token], index: usize) -> bool {
    SECURE_HOSTS.contains(&path)
        && ident(tokens, index + 1) != Some("as")
        && (!in_use_import(tokens, index) || is_module_path(tokens, index, "tokio", "net"))
}

fn is_allowed_module_path(path: &str, tokens: &[Token], index: usize, name: &str) -> bool {
    match (name, ident(tokens, index.wrapping_sub(3))) {
        ("net", Some("std")) => {
            path == HTTP_HOST
                && ident(tokens, index + 3) == Some("SocketAddr")
                && ident(tokens, index + 4) != Some("as")
        }
        ("net", Some("tokio")) => {
            SECURE_HOSTS.contains(&path)
                && ident(tokens, index + 3) == Some("TcpListener")
                && ident(tokens, index + 4) != Some("as")
        }
        _ => false,
    }
}

fn is_allowed_host_import(path: &str, tokens: &[Token], index: usize, name: &str) -> bool {
    path == HTTP_HOST
        && ident(tokens, index + 1) != Some("as")
        && match name {
            "hyper" => {
                in_use_import(tokens, index)
                    && ident(tokens, index + 3) == Some("service")
                    && ident(tokens, index + 6) == Some("service_fn")
            }
            "hyper_util" => in_use_import(tokens, index),
            "tokio_rustls" => ident(tokens, index + 3) == Some("TlsAcceptor"),
            _ => false,
        }
}

fn is_exact_core_fmt_write(path: &str, tokens: &[Token], index: usize) -> bool {
    let start = tokens[..index]
        .iter()
        .rposition(|token| matches!(token, Token::Punct(';')))
        .map_or(0, |at| at + 1);
    path == PART_01
        && index == start + 10
        && ident(tokens, start) == Some("use")
        && ident(tokens, start + 1) == Some("core")
        && ident(tokens, start + 4) == Some("fmt")
        && punct(tokens, start + 7, '{')
        && ident(tokens, start + 8) == Some("self")
        && punct(tokens, start + 9, ',')
        && ident(tokens, index + 1) == Some("as")
        && ident(tokens, index + 2) == Some("_")
}

fn is_direct_sink(tokens: &[Token], index: usize, name: &str) -> bool {
    matches!(
        name,
        "write"
            | "try_write"
            | "try_write_vectored"
            | "poll_write"
            | "poll_write_vectored"
            | "write_all"
            | "write_buf"
            | "writable"
            | "send"
            | "send_to"
            | "try_send_to"
            | "poll_send"
            | "start_send"
            | "flush"
            | "shutdown"
            | "connect"
    ) && punct(tokens, index.wrapping_sub(1), '.')
        && punct(tokens, index + 1, '(')
}

fn is_allowed_direct_sink(path: &str, tokens: &[Token], index: usize, name: &str) -> bool {
    policy_helpers::is_allowed_control_sink(path, tokens, index, name)
        || (name == "send" && policy_runtime_client::allows_authenticated_send(path, tokens))
        || policy_startup::is_known_runtime_shutdown(path, tokens, index, name)
}

fn is_module_path(tokens: &[Token], index: usize, root: &str, module: &str) -> bool {
    ident(tokens, index.wrapping_sub(6)) == Some(root)
        && ident(tokens, index.wrapping_sub(3)) == Some(module)
        && punct(tokens, index.wrapping_sub(5), ':')
        && punct(tokens, index.wrapping_sub(4), ':')
        && punct(tokens, index.wrapping_sub(2), ':')
        && punct(tokens, index.wrapping_sub(1), ':')
}

fn is_allowed_serde_json(path: &str, tokens: &[Token], index: usize) -> bool {
    let call = ident(tokens, index + 3);
    punct(tokens, index + 1, ':')
        && punct(tokens, index + 2, ':')
        && ((path == RUNTIME_CLIENT && call == Some("from_slice"))
            || (path == TOOL_ACTIVITY && call == Some("from_slice"))
            || (path == HTTP_TELEMETRY
                && call == Some("to_vec")
                && tokens
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| {
                        ident(tokens, *position) == Some("serde_json")
                            && ident(tokens, *position + 3) == Some("to_vec")
                    })
                    .count()
                    == 1))
}

fn is_rusqlite_value(path: &str, tokens: &[Token], index: usize) -> bool {
    path == AGGREGATES
        && !in_use_import(tokens, index)
        && index >= 6
        && ident(tokens, index - 6) == Some("rusqlite")
        && punct(tokens, index - 5, ':')
        && punct(tokens, index - 4, ':')
        && ident(tokens, index - 3) == Some("types")
        && punct(tokens, index - 2, ':')
        && punct(tokens, index - 1, ':')
}

fn is_legacy_string(path: &str, tokens: &[Token], index: usize) -> bool {
    if path == TOOL_ACTIVITY {
        return true;
    }
    let field = index.checked_sub(2).and_then(|at| ident(tokens, at));
    (path == PART_01 && matches!(field, Some("currency" | "application_idempotency_key")))
        || (matches!(path, COMPOSITION | COMPOSITION_INPUT) && field == Some("db_path"))
}

fn follows_dyn_error(tokens: &[Token], index: usize) -> bool {
    let index = index + usize::from(punct(tokens, index + 1, '<')) + 1;
    ident(tokens, index) == Some("dyn") && ident(tokens, index + 1) == Some("Error")
}

fn in_use_import(tokens: &[Token], index: usize) -> bool {
    tokens[..index]
        .iter()
        .rev()
        .take_while(|token| !matches!(token, Token::Punct(';')))
        .any(|token| matches!(token, Token::Ident(name) if name == "use"))
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

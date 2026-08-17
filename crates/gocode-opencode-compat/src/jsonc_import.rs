//! Selected OpenCode JSONC import into native typed model.
//!
//! This module is intentionally narrow: it parses a JSONC document, strips
//! comments, and extracts only the fields GOCODE v1 has agreed to translate
//! from OpenCode baseline. Unknown fields are ignored rather than rejected,
//! but every extracted field is typed and validated.

use std::fmt;

/// Error returned when JSONC import cannot produce a normalized native view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsoncImportError {
    /// Input is not valid UTF-8.
    InvalidUtf8,
    /// Comment stripping or JSON parsing failed.
    ParseError(String),
}

impl fmt::Display for JsoncImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => write!(f, "input is not valid UTF-8"),
            Self::ParseError(msg) => write!(f, "JSONC parse error: {msg}"),
        }
    }
}

impl std::error::Error for JsoncImportError {}

/// Native view of selected OpenCode configuration fields.
///
/// This is the output of the fail-closed JSONC importer: only the fields
/// listed here may cross the OpenCode → GOCODE boundary in v1.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NativeConfigImport {
    /// Default provider/model string (e.g. `openai/gpt-4o`).
    pub model: Option<String>,
    /// Small model used for low-cost operations (e.g. title generation).
    pub small_model: Option<String>,
    /// Default agent name.
    pub default_agent: Option<String>,
    /// Server bind host.
    pub server_host: Option<String>,
    /// Server bind port.
    pub server_port: Option<u16>,
    /// Providers explicitly disabled by the user.
    pub disabled_providers: Vec<String>,
}

/// Strips line (`//`) and block (`/* */`) comments from a JSONC document.
///
/// The implementation is a small state machine that preserves comments inside
/// JSON strings. It is sufficient for OpenCode baseline config files.
pub fn strip_jsonc_comments(input: &str) -> Result<String, JsoncImportError> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if in_string {
            output.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                output.push(c);
                in_string = true;
            }
            '/' => match chars.peek() {
                Some('/') => {
                    // Line comment: skip until newline.
                    while let Some(ch) = chars.next() {
                        if ch == '\n' {
                            output.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    // Block comment: skip until */.
                    chars.next(); // consume '*'
                    while let Some(ch) = chars.next() {
                        if ch == '*' && chars.peek() == Some(&'/') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => output.push(c),
            },
            _ => output.push(c),
        }
    }

    Ok(output)
}

/// Imports selected fields from an OpenCode JSONC config document.
///
/// Returns a typed native view. Unknown fields are silently ignored.
pub fn import_opencode_jsonc(input: &str) -> Result<NativeConfigImport, JsoncImportError> {
    let json = strip_jsonc_comments(input)?;
    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| JsoncImportError::ParseError(e.to_string()))?;

    let mut imported = NativeConfigImport::default();

    if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
        imported.model = Some(model.to_owned());
    }
    if let Some(small_model) = value.get("small_model").and_then(|v| v.as_str()) {
        imported.small_model = Some(small_model.to_owned());
    }
    if let Some(default_agent) = value.get("default_agent").and_then(|v| v.as_str()) {
        imported.default_agent = Some(default_agent.to_owned());
    }

    if let Some(server) = value.get("server").and_then(|v| v.as_object()) {
        if let Some(host) = server.get("host").and_then(|v| v.as_str()) {
            imported.server_host = Some(host.to_owned());
        }
        if let Some(port) = server.get("port").and_then(|v| v.as_u64()) {
            if port <= u16::MAX as u64 {
                imported.server_port = Some(port as u16);
            }
        }
    }

    if let Some(disabled) = value.get("disabled_providers").and_then(|v| v.as_array()) {
        imported.disabled_providers = disabled
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    Ok(imported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comments_preserves_strings() {
        let input = r#"{
            // line comment
            "key": "value // not a comment",
            /* block
               comment */
            "other": /* inline */ "value"
        }"#;
        let stripped = strip_jsonc_comments(input).unwrap();
        // The line and block comments should be gone, but the // inside the
        // JSON string must be preserved.
        assert!(!stripped.contains("line comment"));
        assert!(!stripped.contains("block"));
        assert!(stripped.contains("value // not a comment"));
        assert!(stripped.contains("\"other\":  \"value\""));
        // Stripped document must be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&stripped).unwrap();
    }

    #[test]
    fn import_extracts_selected_fields() {
        let input = r#"{
            // OpenCode baseline config
            "model": "openai/gpt-4o",
            "small_model": "openai/gpt-4o-mini",
            "default_agent": "default",
            "server": {
                "host": "127.0.0.1",
                "port": 8080
            },
            "disabled_providers": ["anthropic"],
            "experimental": { "subagents": true } // ignored
        }"#;

        let imported = import_opencode_jsonc(input).unwrap();
        assert_eq!(imported.model, Some("openai/gpt-4o".into()));
        assert_eq!(imported.small_model, Some("openai/gpt-4o-mini".into()));
        assert_eq!(imported.default_agent, Some("default".into()));
        assert_eq!(imported.server_host, Some("127.0.0.1".into()));
        assert_eq!(imported.server_port, Some(8080));
        assert_eq!(imported.disabled_providers, vec!["anthropic"]);
    }

    #[test]
    fn import_ignores_unknown_fields() {
        let input = r#"{ "model": "x", "permission": { "default": "ask" } }"#;
        let imported = import_opencode_jsonc(input).unwrap();
        assert_eq!(imported.model, Some("x".into()));
        assert!(imported.disabled_providers.is_empty());
    }
}

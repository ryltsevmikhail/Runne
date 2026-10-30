use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

pub(crate) const ENVIRONMENT: &str = "linux-coding-agent-v1";

#[derive(Debug)]
pub(crate) struct CodingArguments {
    pub path: String,
    pub content: Vec<u8>,
    pub query: String,
    pub limit: usize,
    pub expected_sha256: Option<String>,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
}

/// Validates bounded relative paths before any descriptor is opened.
pub(crate) fn valid_relative(path: &str, directory: bool) -> bool {
    (directory && path == ".")
        || (!path.is_empty()
            && path.len() <= 255
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path.contains('\0')
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

pub(crate) fn parse(tool: &str, value: &Value) -> Result<CodingArguments, ()> {
    let object = value.as_object().ok_or(())?;
    let directory = matches!(
        tool,
        "workspace.files.list" | "workspace.files.search" | "workspace.command.run"
    );
    let path_key = if tool == "workspace.command.run" {
        "cwd"
    } else {
        "path"
    };
    let path = object.get(path_key).and_then(Value::as_str).ok_or(())?;
    if !valid_relative(path, directory) {
        return Err(());
    }
    let mut parsed = CodingArguments {
        path: path.into(),
        content: vec![],
        query: String::new(),
        limit: 0,
        expected_sha256: None,
        argv: vec![],
        timeout_ms: 0,
    };
    let keys: &[&str] = match tool {
        "workspace.file.read" => &["path"],
        "workspace.file.create_new" => &["path", "content_base64"],
        "workspace.file.replace" => &["path", "content_base64", "expected_sha256"],
        "workspace.files.list" => &["path", "limit"],
        "workspace.files.search" => &["path", "query", "limit"],
        "workspace.command.run" => &["cwd", "argv", "timeout_ms"],
        _ => return Err(()),
    };
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(());
    }
    if let Some(value) = object.get("content_base64") {
        let encoded = value.as_str().ok_or(())?;
        if encoded.len() > 8192 {
            return Err(());
        }
        parsed.content = STANDARD.decode(encoded).map_err(|_| ())?;
        if parsed.content.len() > 8192 {
            return Err(());
        }
    }
    if let Some(value) = object.get("expected_sha256") {
        let hash = value.as_str().ok_or(())?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(());
        }
        parsed.expected_sha256 = Some(hash.into());
    }
    if let Some(value) = object.get("limit") {
        parsed.limit = usize::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?;
        let max = if tool == "workspace.files.search" {
            100
        } else {
            200
        };
        if parsed.limit == 0 || parsed.limit > max {
            return Err(());
        }
    }
    if let Some(value) = object.get("query") {
        parsed.query = value.as_str().ok_or(())?.into();
        if parsed.query.is_empty() || parsed.query.len() > 256 {
            return Err(());
        }
    }
    if let Some(value) = object.get("argv") {
        let args = value.as_array().ok_or(())?;
        if args.is_empty() || args.len() > 64 {
            return Err(());
        }
        for value in args {
            let arg = value.as_str().ok_or(())?;
            if arg.len() > 1024 || arg.contains('\0') {
                return Err(());
            }
            parsed.argv.push(arg.into());
        }
        if parsed.argv[0].is_empty() {
            return Err(());
        }
        parsed.timeout_ms = object.get("timeout_ms").and_then(Value::as_u64).ok_or(())?;
        if parsed.timeout_ms == 0 || parsed.timeout_ms > 120_000 {
            return Err(());
        }
    }
    Ok(parsed)
}

pub(crate) fn operation(tool: &str) -> Result<&'static str, ()> {
    Ok(match tool {
        "workspace.file.read" => "read",
        "workspace.file.create_new" => "create_new",
        "workspace.file.replace" => "replace",
        "workspace.files.list" => "list",
        "workspace.files.search" => "search",
        "workspace.command.run" => "command",
        _ => return Err(()),
    })
}

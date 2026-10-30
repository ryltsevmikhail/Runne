use super::helper_types::PermissionHelperOperationV1 as Op;
use crate::local_command_linux::LinuxCommandError as Error;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::ffi::CString;

pub(super) fn path(value: &str) -> Result<CString, Error> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == ".." || (part == "." && value != "."))
    {
        return Err(Error::Invalid);
    }
    CString::new(value).map_err(|_| Error::Invalid)
}
pub(super) fn validate(
    name: &str,
    args: &Value,
    has_target: bool,
) -> Result<(Op, String, Vec<u8>), Error> {
    let object = args.as_object().ok_or(Error::Invalid)?;
    let (op, keys): (Op, &[&str]) = match name {
        "workspace.file.read" => (Op::Read, &["path"]),
        "workspace.file.create_new" => (Op::CreateNew, &["path", "content_base64"]),
        "workspace.files.list" => (Op::List, &["path", "limit"]),
        "workspace.files.search" => (Op::Search, &["path", "query", "limit"]),
        "workspace.file.replace" => (Op::Replace, &["path", "expected_sha256", "content_base64"]),
        "workspace.command.run" => (Op::Command, &["cwd", "argv", "timeout_ms"]),
        _ => return Err(Error::Invalid),
    };
    if object.len() != keys.len()
        || keys.iter().any(|k| !object.contains_key(*k))
        || has_target == (op == Op::CreateNew)
    {
        return Err(Error::Invalid);
    }
    let target = args[if op == Op::Command { "cwd" } else { "path" }]
        .as_str()
        .ok_or(Error::Invalid)?;
    path(target)?;
    if target == "." && !op.is_directory() {
        return Err(Error::Invalid);
    }
    let mut content = Vec::new();
    if matches!(op, Op::CreateNew | Op::Replace) {
        let encoded = args["content_base64"].as_str().ok_or(Error::Invalid)?;
        if encoded.len() > 8192 {
            return Err(Error::Invalid);
        }
        content = STANDARD.decode(encoded).map_err(|_| Error::Invalid)?;
    }
    if op == Op::Replace {
        let digest = args["expected_sha256"].as_str().ok_or(Error::Invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
    }
    if matches!(op, Op::List | Op::Search) {
        let max = if op == Op::List { 200 } else { 100 };
        if !args["limit"].as_u64().is_some_and(|n| n > 0 && n <= max) {
            return Err(Error::Invalid);
        }
    }
    if op == Op::Search
        && !args["query"]
            .as_str()
            .is_some_and(|q| !q.is_empty() && q.len() <= 256)
    {
        return Err(Error::Invalid);
    }
    if op == Op::Command {
        let argv = args["argv"].as_array().ok_or(Error::Invalid)?;
        if argv.is_empty()
            || argv.len() > 64
            || argv.iter().any(|v| {
                !v.as_str()
                    .is_some_and(|s| s.len() <= 1024 && !s.contains('\0'))
            })
            || argv[0].as_str() == Some("")
            || !args["timeout_ms"]
                .as_u64()
                .is_some_and(|t| t > 0 && t <= 120000)
        {
            return Err(Error::Invalid);
        }
    }
    Ok((op, target.into(), content))
}

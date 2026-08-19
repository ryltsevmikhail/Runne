use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use super::{lexer, parser::declarations, policy_io::audit_tokens};

pub(super) fn resolve_closure(
    workspace: &Path,
    roots: &[&str],
) -> Result<BTreeSet<String>, String> {
    let mut files = BTreeSet::new();
    for root in roots {
        visit(&workspace.join(root), workspace, &mut files)?;
    }
    Ok(files)
}

fn visit(path: &Path, workspace: &Path, files: &mut BTreeSet<String>) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("unresolved production module: {}", path.display()));
    }
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| format!("source outside workspace: {}", path.display()))?
        .display()
        .to_string();
    if !files.insert(relative.clone()) {
        return Ok(());
    }
    let source = fs::read_to_string(path)
        .map_err(|_| format!("unreadable production module: {}", path.display()))?;
    let tokens = lexer::tokenize(&source)
        .map_err(|error| format!("unresolved production module {}: {error}", path.display()))?;
    audit_tokens(&relative, &tokens)
        .map_err(|error| format!("production token policy {relative}: {error}"))?;
    let module_directory = module_directory(path)?;
    for declaration in declarations(&tokens)
        .map_err(|error| format!("unresolved production module {}: {error}", path.display()))?
    {
        if declaration.cfg_test {
            continue;
        }
        let directory = module_directory.join(declaration.directory);
        let child = match declaration.path {
            Some(path) => directory.join(path),
            None => resolve_default_module(&directory, &declaration.name).ok_or_else(|| {
                format!(
                    "unresolved production module `{}` declared by {}",
                    declaration.name,
                    path.display()
                )
            })?,
        };
        visit(&child, workspace, files)?;
    }
    Ok(())
}

fn module_directory(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("module without parent: {}", path.display()))?;
    if path.file_name().is_some_and(|name| name == "mod.rs") {
        return Ok(parent.to_owned());
    }
    let stem = path
        .file_stem()
        .ok_or_else(|| format!("module without stem: {}", path.display()))?;
    Ok(parent.join(stem))
}

fn resolve_default_module(directory: &Path, name: &str) -> Option<PathBuf> {
    let file = directory.join(format!("{name}.rs"));
    if file.is_file() {
        Some(file)
    } else {
        let module = directory.join(name).join("mod.rs");
        module.is_file().then_some(module)
    }
}

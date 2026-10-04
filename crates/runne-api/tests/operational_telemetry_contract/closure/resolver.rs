use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use super::{lexer, parser::declarations, policy_io::audit_tokens};

pub(super) fn resolve_closure(
    workspace: &Path,
    roots: &[&str],
) -> Result<BTreeSet<String>, String> {
    let workspace = workspace
        .canonicalize()
        .map_err(|_| format!("unresolved workspace: {}", workspace.display()))?;
    let mut files = BTreeSet::new();
    for root in roots {
        visit(&workspace.join(root), &workspace, &mut files)?;
    }
    Ok(files)
}

fn visit(path: &Path, workspace: &Path, files: &mut BTreeSet<String>) -> Result<(), String> {
    let path = path
        .canonicalize()
        .map_err(|_| format!("unresolved production module: {}", path.display()))?;
    if !path.starts_with(workspace) {
        return Err(format!("source outside workspace: {}", path.display()));
    }
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| format!("source outside workspace: {}", path.display()))?
        .display()
        .to_string();
    if !files.insert(relative.clone()) {
        return Ok(());
    }
    let source = fs::read_to_string(&path)
        .map_err(|_| format!("unreadable production module: {}", path.display()))?;
    let tokens = lexer::tokenize(&source)
        .map_err(|error| format!("unresolved production module {}: {error}", path.display()))?;
    audit_tokens(&relative, &tokens)
        .map_err(|error| format!("production token policy {relative}: {error}"))?;
    let includes = super::parser::item_includes(&relative, &tokens)
        .map_err(|error| format!("unresolved production include {relative}: {error}"))?;
    let module_directory = module_directory(&path)?;
    for declaration in declarations(&tokens)
        .map_err(|error| format!("unresolved production module {}: {error}", path.display()))?
    {
        if declaration.cfg_test {
            continue;
        }
        let child = match declaration.path {
            Some(module_path) if declaration.directory.as_os_str().is_empty() => path
                .parent()
                .ok_or_else(|| format!("module without parent: {}", path.display()))?
                .join(module_path),
            Some(module_path) => module_directory
                .join(declaration.directory)
                .join(module_path),
            None => {
                let directory = module_directory.join(declaration.directory);
                resolve_default_module(&directory, &declaration.name).ok_or_else(|| {
                    format!(
                        "unresolved production module `{}` declared by {}",
                        declaration.name,
                        path.display()
                    )
                })?
            }
        };
        visit(&child, workspace, files)?;
    }
    for include in includes {
        let include_path = Path::new(&include.path);
        if include_path.as_os_str().is_empty()
            || include_path.is_absolute()
            || include_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("unsafe production include in {relative}"));
        }
        let child = path
            .parent()
            .ok_or_else(|| format!("include without parent: {relative}"))?
            .join(include_path);
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

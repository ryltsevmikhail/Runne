#![cfg(test)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ALLOWED_WRITER_FIXTURES: &[&str] = &[
    "application/workspace_internal/provider_dependencies/credential_writer_fixture.rs",
    "canonical_provider/credential_versions/fixture_lifecycle.rs",
    "canonical_provider/credential_versions/fixture_source.rs",
    "canonical_provider/credential_versions/tests.rs",
    "canonical_provider/credential_versions/tests/provisioning.rs",
    "canonical_provider/credential_versions/tests/provisioning/source_revision.rs",
    "canonical_provider/credential_versions/tests/startup.rs",
    "protected_activation/loopback_fixture/credential_versions.rs",
    "source_boundary_tests.rs",
    "source_boundary_tests/source_tree.rs",
];

const FORBIDDEN: &[&str] = &[
    "NativeProviderCredentialStore",
    "NativeProviderCredentialVersionStore",
    "ProviderCredentialStore",
    "NativeCredentialAuthority",
    "LoopbackCredentialVersionStoreFactory",
    "create_version",
    "delete_version",
    "load_provider_credential_source",
    "provider_credential_status",
];

pub(super) fn daemon_source_violations(source: &Path) -> Vec<String> {
    collect_source_tree_violations(source, ALLOWED_WRITER_FIXTURES)
}

pub(super) fn collect_source_tree_violations(source: &Path, allowed: &[&str]) -> Vec<String> {
    let allowed = allowed.iter().map(PathBuf::from).collect::<BTreeSet<_>>();
    let mut files = Vec::new();
    collect_source_files(source, &mut files);
    files.sort();

    let present = files
        .iter()
        .filter_map(|path| path.strip_prefix(source).ok().map(Path::to_path_buf))
        .collect::<BTreeSet<_>>();
    let mut violations = allowed
        .difference(&present)
        .map(|path| format!("{}: allowlisted writer fixture is missing", path.display()))
        .collect::<Vec<_>>();

    for path in files {
        let relative = path.strip_prefix(source).unwrap_or(&path);
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        if allowed.contains(relative) {
            if !contents.starts_with("#![cfg(test)]\n") {
                violations.push(format!(
                    "{}: allowed writer fixture must begin with #![cfg(test)]",
                    relative.display()
                ));
            }
            continue;
        }

        let normalized = contents.replace("r#", "");
        collect_indirection_violations(source, &path, relative, &normalized, &mut violations);
        for (index, line) in normalized.lines().enumerate() {
            for forbidden in FORBIDDEN {
                if line.contains(forbidden) {
                    violations.push(format!("{}:{}: {forbidden}", relative.display(), index + 1));
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

fn collect_indirection_violations(
    source: &Path,
    file: &Path,
    relative: &Path,
    contents: &str,
    violations: &mut Vec<String>,
) {
    let compact = contents
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    for invocation in identifier_tails(&compact, "include") {
        let (argument, closing) = if let Some(argument) = invocation.strip_prefix("!(") {
            (argument, ')')
        } else if let Some(argument) = invocation.strip_prefix("!{") {
            (argument, '}')
        } else if let Some(argument) = invocation.strip_prefix("![") {
            (argument, ']')
        } else {
            violations.push(format!(
                "{}: dynamic source indirection is forbidden",
                relative.display()
            ));
            continue;
        };
        match direct_string_literal(argument) {
            Some((target, tail)) if tail.starts_with(closing) => {
                validate_target(source, file, relative, target, violations);
            }
            _ => violations.push(format!(
                "{}: dynamic source indirection is forbidden",
                relative.display()
            )),
        }
    }
    for path_tail in identifier_tails(&compact, "path") {
        let Some(assignment) = path_tail.strip_prefix('=') else {
            if path_tail.starts_with('/') {
                violations.push(format!(
                    "{}: dynamic source indirection is forbidden",
                    relative.display()
                ));
            }
            continue;
        };
        match direct_string_literal(assignment) {
            Some((target, _)) => validate_target(source, file, relative, target, violations),
            None if starts_string_literal(assignment) || assignment.starts_with('/') => {
                violations.push(format!(
                    "{}: dynamic source indirection is forbidden",
                    relative.display()
                ));
            }
            None => {}
        }
    }
}

fn identifier_tails<'a>(contents: &'a str, identifier: &str) -> Vec<&'a str> {
    occurrences(contents, identifier)
        .filter(|(offset, tail)| {
            identifier_boundary(contents, *offset)
                && tail
                    .chars()
                    .next()
                    .is_none_or(|character| !(character.is_alphanumeric() || character == '_'))
        })
        .map(|(_, tail)| tail)
        .collect()
}

fn occurrences<'a>(contents: &'a str, marker: &str) -> impl Iterator<Item = (usize, &'a str)> {
    contents
        .match_indices(marker)
        .map(move |(offset, _)| (offset, &contents[offset + marker.len()..]))
}

fn identifier_boundary(contents: &str, offset: usize) -> bool {
    contents[..offset]
        .chars()
        .next_back()
        .is_none_or(|character| !(character.is_alphanumeric() || character == '_'))
}

fn direct_string_literal(argument: &str) -> Option<(&str, &str)> {
    let literal = argument.strip_prefix('"')?;
    let end = literal.find('"')?;
    let target = &literal[..end];
    if target.contains('\\') {
        return None;
    }
    Some((target, &literal[end + 1..]))
}

fn starts_string_literal(argument: &str) -> bool {
    argument.starts_with('"') || argument.starts_with("r\"") || argument.starts_with("r#")
}

fn validate_target(
    source: &Path,
    file: &Path,
    relative: &Path,
    target: &str,
    violations: &mut Vec<String>,
) {
    if !target_stays_within(source, file, target) {
        violations.push(format!(
            "{}: source indirection escapes scan root: {target}",
            relative.display()
        ));
    }
}

fn target_stays_within(source: &Path, file: &Path, target: &str) -> bool {
    let normalized = target.replace('\\', "/");
    if normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized.as_bytes().get(1) == Some(&b':')
    {
        return false;
    }
    let Some(parent) = file
        .parent()
        .and_then(|path| path.strip_prefix(source).ok())
    else {
        return false;
    };
    let mut depth = parent.components().count();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." if depth == 0 => return false,
            ".." => depth -= 1,
            _ => depth += 1,
        }
    }
    true
}

fn collect_source_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
    for entry in entries {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        assert!(!file_type.is_symlink(), "source symlink is forbidden");
        let path = entry.path();
        if file_type.is_dir() {
            collect_source_files(&path, files);
        } else if file_type.is_file() {
            files.push(path);
        }
    }
}

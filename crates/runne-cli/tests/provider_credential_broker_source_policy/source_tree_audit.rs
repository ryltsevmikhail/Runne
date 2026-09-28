use std::path::{Path, PathBuf};

use syn::File;
use syn::visit::Visit;

use super::source_tree_helpers::macro_identifiers;

#[path = "source_tree_visitor.rs"]
mod visitor;
use visitor::{SourceVisitor, SurfaceCounts};

const PROVIDER_CREDENTIAL: &str = "cli/provider_credential.rs";
const BROKER: &str = "cli/provider_credential_broker.rs";
const PERSISTENT_REFERENCE_PROBE: &str = "persistent_reference_probe.rs";
const TASK_RUN: &str = "cli/task_run.rs";
const RAW_RECEIVER_IDENTIFIERS: &[&str] = &[
    "recvmsg",
    "RecvMsg",
    "RecvAncillary",
    "RecvAncillaryBuffer",
    "RecvAncillaryMessage",
    "SCM_RIGHTS",
    "ScmRights",
    "SocketAncillary",
    "from_raw_fd",
    "borrow_raw",
    "STDIN_FILENO",
];

pub fn source_tree_violations(root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let mut violations = Vec::new();
    collect_rust_sources(root, &mut paths, &mut violations);
    paths.sort();
    let mut counts = SurfaceCounts::default();
    for path in paths {
        audit_file(root, &path, &mut counts, &mut violations);
    }
    // Two provider-credential prompt paths plus two headless exec prompt
    // paths (TTY check and piped read), reviewed for D1.4b on 2026-09-28.
    if counts.stdin != 4 {
        violations.push(format!(
            "expected exactly four reviewed std::io::stdin paths, found {}",
            counts.stdin
        ));
    }
    if counts.authority_receive != 1 {
        violations.push(format!(
            "expected exactly one authority receive_from_stdin path, found {}",
            counts.authority_receive
        ));
    }
    if counts.pinned_observe != 1 {
        violations.push(format!(
            "expected exactly one pinned writer observation, found {}",
            counts.pinned_observe
        ));
    }
    if counts.probe_output_channel != 1 {
        violations.push(format!(
            "expected exactly one reviewed persistent-reference output channel, found {}",
            counts.probe_output_channel
        ));
    }
    violations
}

fn collect_rust_sources(root: &Path, paths: &mut Vec<PathBuf>, violations: &mut Vec<String>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            violations.push(format!("cannot scan {}: {error}", root.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                violations.push(format!("cannot read source entry: {error}"));
                continue;
            }
        };
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                violations.push(format!("cannot inspect {}: {error}", path.display()));
                continue;
            }
        };
        if kind.is_symlink() {
            violations.push(format!(
                "symbolic link source is forbidden: {}",
                path.display()
            ));
        } else if kind.is_dir() {
            collect_rust_sources(&path, paths, violations);
        } else if kind.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "rs" || extension == "inc")
        {
            paths.push(path);
        }
    }
}

fn audit_file(root: &Path, path: &Path, counts: &mut SurfaceCounts, violations: &mut Vec<String>) {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("cannot read {relative}: {error}"));
            return;
        }
    };
    if path.extension().is_some_and(|extension| extension == "inc") {
        audit_included_tokens(&relative, &source, violations);
        return;
    }
    let file: File = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => {
            violations.push(format!("cannot parse {relative}: {error}"));
            return;
        }
    };
    SourceVisitor {
        relative: &relative,
        counts,
        violations,
    }
    .visit_file(&file);
}

fn audit_included_tokens(relative: &str, source: &str, violations: &mut Vec<String>) {
    let tokens = match source.parse::<proc_macro2::TokenStream>() {
        Ok(tokens) => tokens,
        Err(error) => {
            violations.push(format!("cannot tokenize {relative}: {error}"));
            return;
        }
    };
    for identifier in macro_identifiers(tokens) {
        if RAW_RECEIVER_IDENTIFIERS.contains(&identifier.as_str())
            || identifier == "stdin"
            || identifier == "receive_from_stdin"
            || identifier == "observe_current_pinned_writer_session"
            || identifier == "include"
            || identifier == "path"
        {
            violations.push(format!("{relative} contains forbidden {identifier}"));
        }
    }
}

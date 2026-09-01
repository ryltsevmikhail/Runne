use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Attribute, Expr, File, Item, ItemMod, Lit, Meta, UseTree};

const PRINT_MACROS: &[&str] = &["print", "println", "eprint", "eprintln"];
const PANIC_MACROS: &[&str] = &[
    "panic",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "unreachable",
    "todo",
    "unimplemented",
];

pub fn broker_disclosure_sink_violations(root: &Path) -> Vec<String> {
    let Some(boundary) = root.parent() else {
        return vec!["broker root has no parent".into()];
    };
    let mut visited = BTreeSet::new();
    let mut violations = Vec::new();
    audit_module_file(root, boundary, &mut visited, &mut violations);
    violations
}

pub fn disclosure_sink_violations(relative: &str, source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => return vec![format!("cannot parse {relative}: {error}")],
    };
    let mut violations = Vec::new();
    SinkVisitor {
        relative,
        violations: &mut violations,
    }
    .visit_file(&file);
    violations
}

fn audit_module_file(
    path: &Path,
    boundary: &Path,
    visited: &mut BTreeSet<PathBuf>,
    violations: &mut Vec<String>,
) {
    let path = path.to_path_buf();
    if !path.starts_with(boundary) || !visited.insert(path.clone()) {
        return;
    }
    let relative = path
        .strip_prefix(boundary)
        .unwrap_or(&path)
        .to_string_lossy();
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            violations.push(format!("cannot read {relative}: {error}"));
            return;
        }
    };
    violations.extend(disclosure_sink_violations(&relative, &source));
    let file: File = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(_) => return,
    };
    discover_modules(&file.items, &path, boundary, visited, violations);
}

fn discover_modules(
    items: &[Item],
    parent: &Path,
    boundary: &Path,
    visited: &mut BTreeSet<PathBuf>,
    violations: &mut Vec<String>,
) {
    for module in items.iter().filter_map(|item| match item {
        Item::Mod(module) if !cfg_test_only(&module.attrs) => Some(module),
        _ => None,
    }) {
        if let Some((_, items)) = &module.content {
            discover_modules(items, parent, boundary, visited, violations);
        } else if let Some(path) = module_path(parent, module) {
            audit_module_file(&path, boundary, visited, violations);
        } else {
            violations.push(format!(
                "cannot resolve production broker module {}",
                module.ident
            ));
        }
    }
}

fn module_path(parent: &Path, module: &ItemMod) -> Option<PathBuf> {
    if let Some(path) = path_attribute(&module.attrs) {
        return parent.parent().map(|directory| directory.join(path));
    }
    let directory = if parent.file_name().is_some_and(|name| name == "mod.rs") {
        parent.parent()?.to_path_buf()
    } else {
        parent.parent()?.join(parent.file_stem()?)
    };
    let direct = directory.join(format!("{}.rs", module.ident));
    if direct.is_file() {
        Some(direct)
    } else {
        let nested = directory.join(module.ident.to_string()).join("mod.rs");
        nested.is_file().then_some(nested)
    }
}

fn path_attribute(attributes: &[Attribute]) -> Option<PathBuf> {
    attributes.iter().find_map(|attribute| {
        let Meta::NameValue(value) = &attribute.meta else {
            return None;
        };
        if !value.path.is_ident("path") {
            return None;
        }
        let Expr::Lit(literal) = &value.value else {
            return None;
        };
        let Lit::Str(path) = &literal.lit else {
            return None;
        };
        Some(PathBuf::from(path.value()))
    })
}

fn cfg_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        if !list.path.is_ident("cfg") {
            return false;
        }
        let mut tokens = list.tokens.clone().into_iter();
        matches!(tokens.next(), Some(proc_macro2::TokenTree::Ident(name)) if name == "test")
            && tokens.next().is_none()
    })
}

struct SinkVisitor<'a> {
    relative: &'a str,
    violations: &'a mut Vec<String>,
}

impl SinkVisitor<'_> {
    fn reject(&mut self, sink: &str) {
        self.violations
            .push(format!("{} contains forbidden {sink}", self.relative));
    }

    fn reject_named_sink(&mut self, name: &syn::Ident) {
        if PRINT_MACROS.iter().any(|sink| name == sink) {
            self.reject("print macro");
        } else if name == "dbg" {
            self.reject("debug macro");
        } else if PANIC_MACROS.iter().any(|sink| name == sink) || name == "panic_any" {
            self.reject("panic sink");
        } else if name == "stdout" || name == "stderr" {
            self.reject("stdout/stderr sink");
        }
    }
}

impl<'ast> Visit<'ast> for SinkVisitor<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let first = node.path.segments.first().map(|segment| &segment.ident);
        let last = node.path.segments.last().map(|segment| &segment.ident);
        if last.is_some_and(|name| PRINT_MACROS.iter().any(|sink| name == sink)) {
            self.reject("print macro");
        } else if last.is_some_and(|name| name == "dbg") {
            self.reject("debug macro");
        } else if last.is_some_and(|name| PANIC_MACROS.iter().any(|sink| name == sink)) {
            self.reject("panic sink");
        } else if first.is_some_and(|name| name == "log") {
            self.reject("log sink");
        } else if first.is_some_and(|name| name == "tracing") {
            self.reject("tracing sink");
        }
        visit::visit_macro(self, node);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let first = path.segments.first().map(|segment| &segment.ident);
        let last = path.segments.last().map(|segment| &segment.ident);
        if first.is_some_and(|name| name == "log") {
            self.reject("log sink");
        } else if first.is_some_and(|name| name == "tracing") {
            self.reject("tracing sink");
        } else if last.is_some_and(|name| PRINT_MACROS.iter().any(|sink| name == sink)) {
            self.reject("print macro");
        } else if last.is_some_and(|name| name == "dbg") {
            self.reject("debug macro");
        } else if last.is_some_and(|name| PANIC_MACROS.iter().any(|sink| name == sink)) {
            self.reject("panic sink");
        } else if last.is_some_and(|name| name == "stdout" || name == "stderr") {
            self.reject("stdout/stderr sink");
        } else if last.is_some_and(|name| name == "panic_any") {
            self.reject("panic sink");
        }
        visit::visit_path(self, path);
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        match tree {
            UseTree::Path(path) if path.ident == "log" => self.reject("log sink"),
            UseTree::Path(path) if path.ident == "tracing" => self.reject("tracing sink"),
            UseTree::Path(path) => self.reject_named_sink(&path.ident),
            UseTree::Name(name) => self.reject_named_sink(&name.ident),
            UseTree::Rename(rename) => self.reject_named_sink(&rename.ident),
            UseTree::Glob(_) | UseTree::Group(_) => {}
        }
        visit::visit_use_tree(self, tree);
    }
}

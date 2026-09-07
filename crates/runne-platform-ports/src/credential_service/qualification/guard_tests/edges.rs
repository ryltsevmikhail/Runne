use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Lit, LitStr, Macro, Meta};

pub(super) struct Child {
    pub(super) path: PathBuf,
    pub(super) test_only: bool,
}

struct IncludeVisitor {
    includes: Vec<Result<PathBuf, &'static str>>,
    nested_tokens: Vec<String>,
    ambiguous: bool,
}

impl<'ast> Visit<'ast> for IncludeVisitor {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac.path.is_ident("include") {
            self.includes.push(
                syn::parse2::<LitStr>(mac.tokens.clone())
                    .map(|literal| PathBuf::from(literal.value()))
                    .map_err(|_| "include! argument is not a string literal"),
            );
        } else {
            let tokens = mac.tokens.to_string();
            if tokens.contains("include") {
                if find_include_macro(&tokens).is_some() {
                    self.nested_tokens.push(tokens.clone());
                } else if contains_identifier(&tokens, "include") {
                    self.ambiguous = true;
                }
            }
            if mac.path.is_ident("macro_rules") && has_parameterized_macro_callee(&tokens) {
                self.ambiguous = true;
            }
        }
        visit::visit_macro(self, mac);
    }
}

pub(super) fn collect_includes(
    path: &Path,
    item: &Item,
    test_only: bool,
    children: &mut Vec<Child>,
    findings: &mut Vec<String>,
) {
    let mut visitor = IncludeVisitor {
        includes: Vec::new(),
        nested_tokens: Vec::new(),
        ambiguous: false,
    };
    visitor.visit_item(item);
    for include in visitor.includes {
        let relative = match include {
            Ok(relative) => relative,
            Err(reason) => {
                findings.push(format!("{} in {}", reason, path.display()));
                continue;
            }
        };
        add_include_child(path, relative, test_only, children, findings);
    }
    for tokens in visitor.nested_tokens {
        collect_raw_includes_from_text(path, &tokens, test_only, children, findings);
    }
    if visitor.ambiguous {
        findings.push(format!(
            "ambiguous macro include token flow in {}",
            path.display()
        ));
    }
}

fn contains_identifier(source: &str, expected: &str) -> bool {
    source
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|token| token == expected)
}

fn has_parameterized_macro_callee(tokens: &str) -> bool {
    let compact: String = tokens
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for suffix in compact.split('$').skip(1) {
        let Some((name, remainder)) = suffix.split_once(':') else {
            continue;
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character == '_' || character.is_alphanumeric())
            || !remainder.starts_with("ident")
        {
            continue;
        }
        if compact.contains(&format!("${name}!")) {
            return true;
        }
    }
    false
}

pub(super) fn collect_raw_includes(
    path: &Path,
    source: &str,
    test_only: bool,
    findings: &mut Vec<String>,
) -> Vec<Child> {
    let mut children = Vec::new();
    collect_raw_includes_from_text(path, source, test_only, &mut children, findings);
    children
}

pub(super) fn collect_raw_includes_from_text(
    path: &Path,
    source: &str,
    test_only: bool,
    children: &mut Vec<Child>,
    findings: &mut Vec<String>,
) {
    let mut remainder = source;
    while let Some((_, bang_end)) = find_include_macro(remainder) {
        let after_macro = &remainder[bang_end..];
        let Some(open) = after_macro.find('(') else {
            findings.push(format!("malformed include! in {}", path.display()));
            return;
        };
        let Some(close) = after_macro[open + 1..].find(')') else {
            findings.push(format!("unterminated include! in {}", path.display()));
            return;
        };
        let arguments = &after_macro[open + 1..open + 1 + close];
        let Ok(relative) = syn::parse_str::<LitStr>(arguments.trim()) else {
            findings.push(format!("dynamic include! in {}", path.display()));
            remainder = &after_macro[open + 1 + close + 1..];
            continue;
        };
        add_include_child(
            path,
            PathBuf::from(relative.value()),
            test_only,
            children,
            findings,
        );
        let consumed = bang_end + open + close + 2;
        remainder = &remainder[consumed..];
    }
}

fn find_include_macro(source: &str) -> Option<(usize, usize)> {
    let mut offset = 0;
    while let Some(relative) = source[offset..].find("include") {
        let index = offset + relative;
        let before_is_ident = source[..index]
            .chars()
            .next_back()
            .is_some_and(|character| character == '_' || character.is_alphanumeric());
        let mut bang = index + "include".len();
        while source
            .as_bytes()
            .get(bang)
            .is_some_and(u8::is_ascii_whitespace)
        {
            bang += 1;
        }
        if !before_is_ident && source.as_bytes().get(bang) == Some(&b'!') {
            return Some((index, bang + 1));
        }
        offset = bang;
    }
    None
}

fn add_include_child(
    path: &Path,
    relative: PathBuf,
    test_only: bool,
    children: &mut Vec<Child>,
    findings: &mut Vec<String>,
) {
    let included = if relative.is_absolute() {
        relative
    } else {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(relative)
    };
    if !included.is_file() {
        findings.push(format!(
            "include! target {} from {} does not exist",
            included.display(),
            path.display()
        ));
        return;
    }
    children.push(Child {
        path: included,
        test_only,
    });
}

pub(super) fn external_module_path(
    parent: &Path,
    module: &str,
    attrs: &[Attribute],
) -> Option<PathBuf> {
    if let Some(path) = path_attribute(attrs) {
        return Some(parent.parent().unwrap_or(parent).join(path));
    }
    let directory = parent.parent()?;
    let file_name = parent.file_name().and_then(|name| name.to_str());
    let base = if matches!(file_name, Some("lib.rs" | "main.rs" | "mod.rs")) {
        directory.to_path_buf()
    } else {
        directory.join(parent.file_stem()?)
    };
    let flat = base.join(format!("{module}.rs"));
    if flat.is_file() {
        Some(flat)
    } else {
        let nested = base.join(module).join("mod.rs");
        if nested.is_file() {
            Some(nested)
        } else {
            let sibling = directory.join(format!("{module}.rs"));
            sibling.is_file().then_some(sibling)
        }
    }
}

fn path_attribute(attrs: &[Attribute]) -> Option<PathBuf> {
    attrs.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        let Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        let Expr::Lit(expression) = &name_value.value else {
            return None;
        };
        let Lit::Str(literal) = &expression.lit else {
            return None;
        };
        Some(PathBuf::from(literal.value()))
    })
}

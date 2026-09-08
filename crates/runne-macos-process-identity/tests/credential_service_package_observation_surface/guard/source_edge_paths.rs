use std::path::{Path, PathBuf};

use syn::{Attribute, Expr, ExprLit, Lit, Meta};

pub(super) fn is_builtin_include(path: &syn::Path) -> bool {
    path.is_ident("include")
        || path.segments.len() == 2
            && path.segments[0].ident == "std"
            && path.segments[1].ident == "include"
}

pub(super) fn is_builtin_source_free(path: &syn::Path) -> bool {
    let names = ["compile_error", "global_asm", "thread_local"];
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [name] if names.contains(&name.as_str()))
        || matches!(segments.as_slice(), [root, name]
            if ["core", "std"].contains(&root.as_str()) && names.contains(&name.as_str()))
}

pub(super) fn module_directory(source: &Path) -> PathBuf {
    let parent = source.parent().expect("source has no parent");
    if source
        .extension()
        .is_some_and(|extension| extension == "inc")
    {
        return parent.to_path_buf();
    }
    match source.file_stem().and_then(|stem| stem.to_str()) {
        Some("mod" | "lib" | "main" | "build") => parent.to_path_buf(),
        _ => parent.join(source.file_stem().expect("source has no stem")),
    }
}

pub(super) fn module_path(attributes: &[Attribute]) -> Option<String> {
    let mut result = None;
    for attribute in attributes {
        if attribute.path().is_ident("path") {
            let Meta::NameValue(value) = &attribute.meta else {
                panic!("unsupported path attribute")
            };
            let Expr::Lit(ExprLit {
                lit: Lit::Str(path),
                ..
            }) = &value.value
            else {
                panic!("unsupported path attribute")
            };
            assert!(result.is_none(), "multiple path attributes are unsupported");
            result = Some(path.value());
        } else if attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "path")
        {
            panic!("unsupported qualified path attribute")
        } else if attribute.path().is_ident("cfg_attr")
            && matches!(&attribute.meta, Meta::List(list) if list.tokens.to_string().contains("path"))
        {
            panic!("unsupported conditional path attribute")
        }
    }
    result
}

use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

use super::visitor::{Call, MacroDisposition};

#[derive(Clone, Copy)]
pub(super) enum AttributeTarget {
    Function,
    Impl,
    Trait,
    Other,
}

pub(super) fn collect_opaque_attribute(
    attrs: &[Attribute],
    target: AttributeTarget,
    calls: &mut Vec<Call>,
) {
    let serde_helpers = has_derive_root(attrs, "serde");
    let error_helpers = has_derive_root(attrs, "thiserror");
    for attribute in attrs {
        if attribute.path().is_ident("derive") {
            collect_derives(attribute, calls);
        } else if attribute
            .path()
            .segments
            .first()
            .is_some_and(|s| s.ident == "serde")
        {
            push_attribute(
                attribute,
                serde_helpers.then(|| "serde::helper".to_owned()),
                calls,
            );
        } else if attribute.path().get_ident().is_some_and(|name| {
            matches!(
                name.to_string().as_str(),
                "backtrace" | "error" | "from" | "source"
            )
        }) {
            push_attribute(
                attribute,
                error_helpers.then(|| {
                    format!(
                        "thiserror::{name}",
                        name = attribute.path().get_ident().unwrap()
                    )
                }),
                calls,
            );
        } else if !is_non_expanding_builtin(attribute, target) {
            push_attribute(
                attribute,
                super::macro_trust::trusted_external_path(attribute.path()),
                calls,
            );
        }
    }
}

fn has_derive_root(attrs: &[Attribute], root: &str) -> bool {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("derive"))
        .any(|attr| {
            attr.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
                .is_ok_and(|paths| {
                    paths.iter().any(|path| {
                        let name = path.segments.last().map(|s| s.ident.to_string());
                        match root {
                            "serde" => matches!(name.as_deref(), Some("Serialize" | "Deserialize")),
                            "thiserror" => name.as_deref() == Some("Error"),
                            _ => false,
                        }
                    })
                })
        })
}

fn collect_derives(attribute: &Attribute, calls: &mut Vec<Call>) {
    let Ok(paths) = attribute.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
    else {
        push_attribute(attribute, None, calls);
        return;
    };
    for path in paths {
        let name = path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let root = match (path.segments.len(), name.as_str()) {
            (
                1,
                "Clone" | "Copy" | "Debug" | "Default" | "Eq" | "Hash" | "Ord" | "PartialEq"
                | "PartialOrd",
            ) => Some("std"),
            (1, "Serialize" | "Deserialize") => Some("serde"),
            (1, "Error") => Some("thiserror"),
            (2, "Serialize" | "Deserialize") if path.segments[0].ident == "serde" => Some("serde"),
            (2, "Error") if path.segments[0].ident == "thiserror" => Some("thiserror"),
            _ => None,
        };
        let trusted = root.map(|root| format!("{root}::{name}"));
        push_named_attribute(name, trusted, calls);
    }
}

fn push_attribute(attribute: &Attribute, trusted_path: Option<String>, calls: &mut Vec<Call>) {
    let name = attribute
        .path()
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    push_named_attribute(name, trusted_path, calls);
}

fn push_named_attribute(name: String, trusted_path: Option<String>, calls: &mut Vec<Call>) {
    calls.push(Call::Macro {
        name,
        disposition: if trusted_path.is_some() {
            MacroDisposition::Unrelated
        } else {
            MacroDisposition::OpaqueExternal
        },
        trusted_path,
        scope: Vec::new(),
        position: 0,
        payload: None,
    });
}

fn is_non_expanding_builtin(attribute: &Attribute, target: AttributeTarget) -> bool {
    if is_inert_tool_attribute(attribute) {
        return true;
    }
    let Some(name) = attribute.path().get_ident().map(ToString::to_string) else {
        return is_diagnostic_builtin(attribute, target);
    };
    if name == "cfg_attr" {
        return is_audited_cfg_attr(attribute);
    }
    if name == "derive" {
        return true;
    }
    if matches!(
        name.as_str(),
        "allow"
            | "cfg"
            | "deprecated"
            | "deny"
            | "doc"
            | "expect"
            | "forbid"
            | "must_use"
            | "macro_export"
            | "non_exhaustive"
            | "path"
            | "repr"
            | "link"
            | "used"
            | "warn"
    ) {
        return true;
    }
    match target {
        AttributeTarget::Function => {
            matches!(
                name.as_str(),
                "cold" | "inline" | "instruction_set" | "target_feature" | "track_caller"
            ) || (name == "unsafe" && is_non_expanding_unsafe_builtin(attribute))
        }
        AttributeTarget::Impl => name == "automatically_derived",
        AttributeTarget::Trait => false,
        AttributeTarget::Other => name == "unsafe" && is_non_expanding_unsafe_builtin(attribute),
    }
}

pub(super) fn impl_item_attrs(item: &syn::ImplItem) -> &[Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

pub(super) fn trait_item_attrs(item: &syn::TraitItem) -> &[Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn is_audited_cfg_attr(attribute: &Attribute) -> bool {
    let Ok(arguments) = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
    else {
        return false;
    };
    if arguments
        .first()
        .is_some_and(super::syntax::cfg_meta_is_false)
    {
        return true;
    }
    arguments.iter().skip(1).all(|meta| {
        meta.path().get_ident().is_some_and(|name| {
            matches!(
                name.to_string().as_str(),
                "allow" | "deprecated" | "deny" | "doc" | "expect" | "forbid" | "warn"
            )
        })
    })
}

fn is_inert_tool_attribute(attribute: &Attribute) -> bool {
    attribute.path().segments.first().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "clippy" | "miri" | "rust_analyzer" | "rustfmt"
        )
    })
}

fn is_diagnostic_builtin(attribute: &Attribute, target: AttributeTarget) -> bool {
    let path = attribute.path();
    let mut segments = path.segments.iter();
    let pair = segments
        .next()
        .zip(segments.next())
        .filter(|_| segments.next().is_none());
    pair.is_some_and(|(tool, name)| {
        tool.ident == "diagnostic"
            && matches!(
                (target, name.ident.to_string().as_str()),
                (AttributeTarget::Trait, "on_unimplemented")
                    | (AttributeTarget::Impl, "do_not_recommend")
            )
    })
}

fn is_non_expanding_unsafe_builtin(attribute: &Attribute) -> bool {
    attribute.parse_args::<syn::Meta>().is_ok_and(|meta| {
        matches!(
            meta.path().get_ident().map(ToString::to_string).as_deref(),
            Some("export_name" | "link_section" | "naked" | "no_mangle")
        )
    })
}

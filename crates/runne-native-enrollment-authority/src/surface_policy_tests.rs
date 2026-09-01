#![cfg(test)]

use std::collections::BTreeMap;
use std::fs;
use syn::{Fields, ImplItem, Item, Visibility};

#[path = "surface_policy_tests/attribute_audit.rs"]
mod attribute_audit;
#[path = "surface_policy_tests/method_audit.rs"]
mod method_audit;
#[path = "surface_policy_tests/mint_call_audit.rs"]
mod mint_call_audit;
#[path = "surface_policy_tests/mutations.rs"]
mod mutations;
#[path = "surface_policy_tests/platform_method_audit.rs"]
mod platform_method_audit;
#[path = "surface_policy_tests/source_discovery.rs"]
mod source_discovery;
#[path = "surface_policy_tests/type_audit.rs"]
mod type_audit;
#[path = "surface_policy_tests/use_audit.rs"]
mod use_audit;
use source_discovery::production_sources;
use type_audit::{is_exact_native_wrapper, opaque_module, opaque_name, type_opaque_name};

const SESSION: &str = "AuthenticatedProviderCredentialWriterSession";
const CLAIM: &str = "AuthenticatedWriterClaimContext";
const EFFECT: &str = "AuthenticatedWriterEffectAdmission";
const HANDOFF: &str = "UntrustedProviderCredentialWriterEndpointHandoffV1";
const PINNED: &str = "PendingPinnedProviderCredentialWriterSessionV1";
const HANDOFF_MODULE: &str = "untrusted_writer_endpoint_handoff";
const OPAQUE_TYPES: [&str; 5] = [SESSION, CLAIM, EFFECT, HANDOFF, PINNED];
const PUBLIC_METHODS: [&str; 6] = [
    "split",
    "receive_from_stdin",
    "observe_current_pinned_writer_session",
    "authenticate_current_writer",
    "into_macos_claim_parts",
    "into_macos_effect_parts",
];

#[test]
fn current_crate_exposes_only_the_exact_opaque_authority_surface() {
    let mut audit = Audit::default();
    for path in production_sources() {
        let source = fs::read_to_string(&path).unwrap();
        let file = syn::parse_file(&source).unwrap();
        audit_items(&file.items, &path.display().to_string(), &mut audit);
    }
    for name in OPAQUE_TYPES {
        if audit.declarations.get(name) != Some(&1) {
            audit.violations.push(format!(
                "expected one public opaque struct declaration for {name}"
            ));
        }
        if audit.reexports.get(name) != Some(&1) {
            audit
                .violations
                .push(format!("expected one exact opaque re-export for {name}"));
        }
    }
    for name in PUBLIC_METHODS {
        if audit.methods.get(name) != Some(&1) {
            audit
                .violations
                .push(format!("expected one exact public {name} method"));
        }
    }
    assert!(audit.violations.is_empty(), "{:#?}", audit.violations);
}

#[derive(Default)]
struct Audit {
    declarations: BTreeMap<&'static str, usize>,
    reexports: BTreeMap<&'static str, usize>,
    methods: BTreeMap<&'static str, usize>,
    violations: Vec<String>,
}

fn authority_surface_violations(source: &str) -> Vec<String> {
    let file = syn::parse_file(source).unwrap();
    let mut audit = Audit::default();
    audit_items(&file.items, "mutation", &mut audit);
    audit.violations
}

fn audit_items(items: &[Item], source: &str, audit: &mut Audit) {
    for item in items {
        if attribute_audit::item_authored_derive(item) {
            audit.violations.push(format!(
                "{source}: authored derive can generate a constructor"
            ));
        }
        match item {
            Item::Struct(item) => audit_struct(item, source, audit),
            Item::Impl(item) => audit_impl(item, source, audit),
            Item::Use(item) => {
                if is_public(&item.vis) {
                    match use_audit::exact_public_reexports(&item.tree, &item.attrs, source) {
                        Ok(names) => {
                            for name in names {
                                *audit.reexports.entry(name).or_default() += 1;
                            }
                        }
                        Err(violation) => audit.violations.push(violation),
                    }
                }
            }
            Item::Mod(item) => {
                if attribute_audit::module_has_forbidden_path(item) {
                    audit.violations.push(format!(
                        "{source}: module path can substitute production source"
                    ));
                }
                let module = normalized_ident(&item.ident);
                if module == HANDOFF_MODULE && !attribute_audit::has_exact_macos_cfg(&item.attrs) {
                    audit
                        .violations
                        .push(format!("{source}: handoff module must use exact macOS cfg"));
                }
                if module == "session" && attribute_audit::has_cfg_or_path_substitution(&item.attrs)
                {
                    audit
                        .violations
                        .push(format!("{source}: session module cannot be substituted"));
                }
                reject_public(&item.vis, "module", source, audit);
                if let Some((_, nested)) = &item.content {
                    audit_items(nested, source, audit);
                }
            }
            Item::Const(item) => reject_public(&item.vis, "constant", source, audit),
            Item::Enum(item) => reject_public(&item.vis, "enum", source, audit),
            Item::ExternCrate(item) => {
                reject_public(&item.vis, "extern crate", source, audit);
            }
            Item::Fn(item) => reject_public(&item.vis, "free function", source, audit),
            Item::Static(item) => reject_public(&item.vis, "static", source, audit),
            Item::Trait(item) => reject_public(&item.vis, "trait", source, audit),
            Item::TraitAlias(item) => reject_public(&item.vis, "trait alias", source, audit),
            Item::Type(item) => reject_public(&item.vis, "type alias", source, audit),
            Item::Union(item) => reject_public(&item.vis, "union", source, audit),
            Item::ForeignMod(_) => audit.violations.push(format!(
                "{source}: foreign module is outside the exact surface"
            )),
            Item::Macro(_) | Item::Verbatim(_) => audit.violations.push(format!(
                "{source}: macro or verbatim item can bypass the audit"
            )),
            _ => audit.violations.push(format!(
                "{source}: unrecognized item is outside the exact surface"
            )),
        }
    }
}

fn audit_struct(item: &syn::ItemStruct, source: &str, audit: &mut Audit) {
    let ident = normalized_ident(&item.ident);
    let name = opaque_name(&ident);
    if let Some(name) = name {
        *audit.declarations.entry(name).or_default() += 1;
    }
    match (is_public(&item.vis), name) {
        (true, None) => audit
            .violations
            .push(format!("{source}: unexpected public struct {ident}")),
        (false, Some(name)) => audit
            .violations
            .push(format!("{source}: opaque struct {name} must be public")),
        _ => {}
    }
    let Some(name) = name else { return };
    if attribute_audit::has_cfg_or_path_substitution(&item.attrs) {
        audit.violations.push(format!(
            "{source}: opaque struct {name} cannot be cfg-substituted"
        ));
    }
    if matches!(item.fields, Fields::Unit) || item.fields.is_empty() {
        audit
            .violations
            .push(format!("{source}: {name} is publicly constructible"));
    }
    for field in &item.fields {
        if !matches!(field.vis, Visibility::Inherited) {
            audit
                .violations
                .push(format!("{source}: {name} has a non-private field"));
        }
    }
    if matches!(name, HANDOFF | PINNED) && !is_exact_native_wrapper(item, name) {
        audit.violations.push(format!(
            "{source}: {name} must retain exactly one private low-level native value"
        ));
    }
}

fn audit_impl(item: &syn::ItemImpl, source: &str, audit: &mut Audit) {
    if item.trait_.is_some() {
        audit
            .violations
            .push(format!("{source}: trait impl is outside the exact surface"));
    }
    let opaque = type_opaque_name(&item.self_ty);
    let platform_parts =
        matches!(opaque, Some(CLAIM | EFFECT)) && attribute_audit::has_exact_macos_cfg(&item.attrs);
    if opaque.is_some()
        && attribute_audit::has_cfg_or_path_substitution(&item.attrs)
        && !platform_parts
    {
        audit
            .violations
            .push(format!("{source}: opaque impl cannot be cfg-substituted"));
    }
    for member in &item.items {
        match member {
            ImplItem::Fn(method) if is_public(&method.vis) => {
                if let Some(name) = method_audit::exact_public_method(item, method) {
                    *audit.methods.entry(name).or_default() += 1;
                } else {
                    audit
                        .violations
                        .push(format!("{source}: unexpected public method"));
                }
            }
            ImplItem::Const(member) => {
                reject_public(&member.vis, "associated constant", source, audit);
            }
            ImplItem::Type(member) => {
                reject_public(&member.vis, "associated type", source, audit);
            }
            ImplItem::Macro(_) | ImplItem::Verbatim(_) => audit.violations.push(format!(
                "{source}: impl macro or verbatim tokens can bypass the audit"
            )),
            ImplItem::Fn(_) => {}
            _ => audit.violations.push(format!(
                "{source}: unrecognized impl item is outside the exact surface"
            )),
        }
    }
}

fn reject_public(visibility: &Visibility, kind: &str, source: &str, audit: &mut Audit) {
    if is_public(visibility) {
        audit
            .violations
            .push(format!("{source}: unexpected public {kind}"));
    }
}

fn normalized_ident(value: &syn::Ident) -> String {
    value.to_string().trim_start_matches("r#").to_owned()
}

const fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

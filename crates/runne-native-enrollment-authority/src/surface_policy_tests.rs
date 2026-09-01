#![cfg(test)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use syn::{Fields, FnArg, ImplItem, Item, ReturnType, Type, UseTree, Visibility};

#[path = "surface_policy_tests/attribute_audit.rs"]
mod attribute_audit;
#[path = "surface_policy_tests/mutations.rs"]
mod mutations;
#[path = "surface_policy_tests/source_discovery.rs"]
mod source_discovery;
use source_discovery::production_sources;

const SESSION: &str = "AuthenticatedProviderCredentialWriterSession";
const CLAIM: &str = "AuthenticatedWriterClaimContext";
const EFFECT: &str = "AuthenticatedWriterEffectAdmission";
const OPAQUE_TYPES: [&str; 3] = [SESSION, CLAIM, EFFECT];

#[test]
fn current_crate_exposes_only_the_consuming_session_split() {
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
                .push(format!("expected one exact session re-export for {name}"));
        }
    }
    assert!(audit.violations.is_empty(), "{:#?}", audit.violations);
}

#[derive(Default)]
struct Audit {
    declarations: BTreeMap<&'static str, usize>,
    reexports: BTreeMap<&'static str, usize>,
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
                    audit_public_use(&item.tree, source, audit);
                }
            }
            Item::Mod(item) => {
                if attribute_audit::module_has_forbidden_path(item) {
                    audit.violations.push(format!(
                        "{source}: module path can substitute production source"
                    ));
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
}

fn audit_impl(item: &syn::ItemImpl, source: &str, audit: &mut Audit) {
    if item.trait_.is_some() {
        audit
            .violations
            .push(format!("{source}: trait impl is outside the exact surface"));
    }
    for member in &item.items {
        match member {
            ImplItem::Fn(method) if is_public(&method.vis) => {
                if !is_exact_consuming_split(item, method) {
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

fn is_exact_consuming_split(item: &syn::ItemImpl, method: &syn::ImplItemFn) -> bool {
    type_opaque_name(&item.self_ty) == Some(SESSION)
        && item.trait_.is_none()
        && method.defaultness.is_none()
        && method.sig.ident == "split"
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && method.sig.inputs.len() == 1
        && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.reference.is_none()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        && returns_exact_split_pair(&method.sig.output)
}

fn returns_exact_split_pair(output: &ReturnType) -> bool {
    let ReturnType::Type(_, value) = output else {
        return false;
    };
    let Type::Tuple(tuple) = value.as_ref() else {
        return false;
    };
    tuple.elems.len() == 2
        && type_opaque_name(&tuple.elems[0]) == Some(CLAIM)
        && type_opaque_name(&tuple.elems[1]) == Some(EFFECT)
}

fn audit_public_use(tree: &UseTree, source: &str, audit: &mut Audit) {
    let mut bindings = Vec::new();
    collect_use_bindings(tree, &mut Vec::new(), &mut bindings);
    for binding in bindings {
        let name = opaque_name(&binding.exposed);
        let exact = name.is_some_and(|name| {
            Path::new(source).file_name().and_then(|file| file.to_str()) == Some("lib.rs")
                && !binding.renamed
                && binding.origin == ["session", name]
                && binding.exposed == name
        });
        if exact {
            *audit.reexports.entry(name.unwrap()).or_default() += 1;
        } else {
            audit.violations.push(format!(
                "{source}: public re-export must originate exactly in session"
            ));
        }
    }
}

struct UseBinding {
    origin: Vec<String>,
    exposed: String,
    renamed: bool,
}

fn collect_use_bindings(tree: &UseTree, prefix: &mut Vec<String>, output: &mut Vec<UseBinding>) {
    match tree {
        UseTree::Name(name) => {
            let ident = normalized_ident(&name.ident);
            let mut origin = prefix.clone();
            origin.push(ident.clone());
            output.push(UseBinding {
                origin,
                exposed: ident,
                renamed: false,
            });
        }
        UseTree::Rename(name) => {
            let mut origin = prefix.clone();
            origin.push(normalized_ident(&name.ident));
            output.push(UseBinding {
                origin,
                exposed: normalized_ident(&name.rename),
                renamed: true,
            });
        }
        UseTree::Path(path) => {
            prefix.push(normalized_ident(&path.ident));
            collect_use_bindings(&path.tree, prefix, output);
            prefix.pop();
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_bindings(item, prefix, output);
            }
        }
        UseTree::Glob(_) => output.push(UseBinding {
            origin: prefix.clone(),
            exposed: "*".to_owned(),
            renamed: false,
        }),
    }
}

fn reject_public(visibility: &Visibility, kind: &str, source: &str, audit: &mut Audit) {
    if is_public(visibility) {
        audit
            .violations
            .push(format!("{source}: unexpected public {kind}"));
    }
}

fn type_opaque_name(value: &Type) -> Option<&'static str> {
    let Type::Path(path) = value else {
        return None;
    };
    path.path
        .segments
        .last()
        .and_then(|segment| opaque_name(&normalized_ident(&segment.ident)))
}

fn normalized_ident(value: &syn::Ident) -> String {
    value.to_string().trim_start_matches("r#").to_owned()
}

fn opaque_name(value: &str) -> Option<&'static str> {
    OPAQUE_TYPES.into_iter().find(|name| *name == value)
}

const fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

use std::collections::HashSet;

use syn::parse::Parser;
use syn::visit::{self, Visit};
use syn::{Fields, ImplItem, Type, UseTree, Visibility};

pub const FACTS: &str = "VerifiedInstalledEnrollmentMeasurementFacts";
pub const EXPECTATION: &str = "QualificationRuntimeInstalledExpectation";
pub const VERIFIED: &str = "VerifiedQualificationAdmission";
const SENSITIVE: [&str; 3] = [FACTS, EXPECTATION, VERIFIED];

pub fn collect_aliases(file: &syn::File) -> HashSet<String> {
    collect_aliases_from(file, &SENSITIVE)
}

pub fn collect_sealed_aliases(file: &syn::File) -> HashSet<String> {
    collect_aliases_from(file, &[EXPECTATION, VERIFIED])
}

pub fn collect_macro_aliases(file: &syn::File) -> HashSet<String> {
    collect_aliases_from(
        file,
        &[
            FACTS,
            EXPECTATION,
            VERIFIED,
            "PendingQualificationAdmission",
        ],
    )
}

fn collect_aliases_from(file: &syn::File, roots: &[&str]) -> HashSet<String> {
    let mut aliases: HashSet<_> = roots.iter().map(|name| (*name).to_owned()).collect();
    loop {
        let before = aliases.len();
        AliasCollector {
            aliases: &mut aliases,
        }
        .visit_file(file);
        if aliases.len() == before {
            return aliases;
        }
    }
}

struct AliasCollector<'a> {
    aliases: &'a mut HashSet<String>,
}

impl<'ast> Visit<'ast> for AliasCollector<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_aliases(&item.tree, false, self.aliases);
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if type_mentions(&item.ty, self.aliases) {
            self.aliases.insert(item.ident.to_string());
        }
        visit::visit_item_type(self, item);
    }
}

fn meta_contains_derive(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("derive") {
        return true;
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    parser
        .parse2(list.tokens.clone())
        .is_ok_and(|nested| nested.iter().any(meta_contains_derive))
}

fn collect_use_aliases(tree: &UseTree, inherited: bool, aliases: &mut HashSet<String>) {
    match tree {
        UseTree::Path(path) => collect_use_aliases(
            &path.tree,
            inherited || aliases.contains(&path.ident.to_string()),
            aliases,
        ),
        UseTree::Name(name) if inherited || aliases.contains(&name.ident.to_string()) => {
            aliases.insert(name.ident.to_string());
        }
        UseTree::Rename(rename) if inherited || aliases.contains(&rename.ident.to_string()) => {
            aliases.insert(rename.rename.to_string());
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_aliases(tree, inherited, aliases);
            }
        }
        _ => {}
    }
}

pub fn sealed_struct(item: &syn::ItemStruct) -> bool {
    matches!(item.fields, Fields::Named(_))
        && item
            .fields
            .iter()
            .all(|field| matches!(field.vis, Visibility::Inherited))
        && !has_forbidden_derive(&item.attrs)
}

pub fn exact_test_support_only(attrs: &[syn::Attribute]) -> bool {
    attrs.len() == 1
        && attrs[0].path().is_ident("cfg")
        && attrs[0]
            .parse_args::<syn::Meta>()
            .is_ok_and(|meta| match meta {
                syn::Meta::NameValue(value) => {
                    value.path.is_ident("feature")
                        && matches!(value.value, syn::Expr::Lit(ref expression)
                            if matches!(expression.lit, syn::Lit::Str(ref value)
                                if value.value() == "test-support"))
                }
                _ => false,
            })
}

fn has_forbidden_derive(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| meta_contains_derive(&attr.meta))
}

pub fn type_name(ty: &Type, aliases: &HashSet<String>) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    let name = path.path.segments.last()?.ident.to_string();
    aliases.contains(&name).then_some(name)
}

pub fn exact_factory(sig: &syn::Signature) -> bool {
    exact_signature(
        sig,
        "fn qualification_runtime_installed_expectation(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3) -> Result<QualificationRuntimeInstalledExpectation, InstalledExpectationError> {}",
    )
}

pub fn exact_verification(sig: &syn::Signature) -> bool {
    exact_signature(
        sig,
        "fn verify_qualification_admission(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: &runne_native_qualification::PendingQualificationAdmission, now_unix_seconds: u64) -> Result<(), QualificationAdmissionError> {}",
    )
}

fn exact_signature(actual: &syn::Signature, expected: &str) -> bool {
    let expected: syn::ImplItemFn = syn::parse_str(expected).unwrap();
    let mut actual = actual.clone();
    let mut expected = expected.sig;
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

pub fn node_mentions_trait(item: &syn::ItemTrait, aliases: &HashSet<String>) -> bool {
    let mut visitor = NameVisitor {
        aliases,
        found: false,
    };
    visitor.visit_item_trait(item);
    visitor.found
}

pub fn fields_mention(fields: &Fields, aliases: &HashSet<String>) -> bool {
    fields.iter().any(|field| type_mentions(&field.ty, aliases))
}

pub fn generics_mention(value: &syn::Generics, aliases: &HashSet<String>) -> bool {
    let mut visitor = NameVisitor {
        aliases,
        found: false,
    };
    visitor.visit_generics(value);
    visitor.found
}

pub fn signature_mentions(value: &syn::Signature, aliases: &HashSet<String>) -> bool {
    let mut visitor = NameVisitor {
        aliases,
        found: false,
    };
    visitor.visit_signature(value);
    visitor.found
}

pub fn type_mentions(value: &Type, aliases: &HashSet<String>) -> bool {
    let mut visitor = NameVisitor {
        aliases,
        found: false,
    };
    visitor.visit_type(value);
    visitor.found
}

pub fn path_mentions(value: &syn::Path, aliases: &HashSet<String>) -> bool {
    value
        .segments
        .iter()
        .any(|segment| aliases.contains(&segment.ident.to_string()))
}

pub fn impl_member_mentions(value: &ImplItem, aliases: &HashSet<String>) -> bool {
    matches!(value, ImplItem::Fn(item) if signature_mentions(&item.sig, aliases))
        || matches!(value, ImplItem::Type(item) if type_mentions(&item.ty, aliases))
        || matches!(value, ImplItem::Const(item) if type_mentions(&item.ty, aliases))
}

struct NameVisitor<'a> {
    aliases: &'a HashSet<String>,
    found: bool,
}

impl Visit<'_> for NameVisitor<'_> {
    fn visit_ident(&mut self, ident: &syn::Ident) {
        self.found |= self.aliases.contains(&ident.to_string());
    }
}

pub fn use_leaves(tree: &UseTree) -> Vec<Vec<String>> {
    let mut leaves = Vec::new();
    collect_use_leaves(tree, &mut Vec::new(), &mut leaves);
    leaves
}

fn collect_use_leaves(tree: &UseTree, prefix: &mut Vec<String>, leaves: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_leaves(&path.tree, prefix, leaves);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut leaf = prefix.clone();
            leaf.push(name.ident.to_string());
            leaves.push(leaf);
        }
        UseTree::Rename(rename) => {
            let mut leaf = prefix.clone();
            leaf.push(rename.ident.to_string());
            leaf.push(rename.rename.to_string());
            leaves.push(leaf);
        }
        UseTree::Glob(_) => {
            let mut leaf = prefix.clone();
            leaf.push("*".into());
            leaves.push(leaf);
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_leaves(tree, prefix, leaves);
            }
        }
    }
}

pub fn exact_reviewed_reexport(source: &str, leaf: &[String]) -> bool {
    leaf.last().is_some_and(|name| name == FACTS)
        && [
            (
                "runne-platform-desktop/src/updater_metadata/enrollment_tuple/daemon_installed.rs",
                "measurement_facts",
            ),
            (
                "runne-platform-desktop/src/updater_metadata/enrollment_tuple.rs",
                "enrollment_daemon_installed",
            ),
            ("runne-platform-desktop/src/lib.rs", "updater_metadata"),
        ]
        .iter()
        .any(|(path, module)| source == *path && leaf.iter().any(|part| part == module))
}

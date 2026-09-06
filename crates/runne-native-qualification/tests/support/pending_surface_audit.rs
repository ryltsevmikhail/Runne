use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use syn::{Fields, ImplItem, ImplItemFn, Item, Visibility};

use crate::pending_public_surface::audit_public_surface;
use crate::pending_surface_aliases::{collect_aliases, ident_is_raw, ident_name, type_name};
use crate::pending_surface_allowlist::exact_admission_impl;
use crate::pending_surface_sources::collect_sources;
use crate::pending_surface_types::expand_family;

const PENDING: &str = "PendingQualificationFault";

pub fn audit_crate(source_root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let mut violations = Vec::new();
    collect_sources(source_root, &mut paths, &mut violations);
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        let relative = path.strip_prefix(source_root).unwrap_or(&path).display();
        match fs::read_to_string(&path) {
            Ok(source) => match syn::parse_file(&source) {
                Ok(file) => files.push((relative.to_string(), file)),
                Err(error) => violations.push(format!("cannot parse {relative}: {error}")),
            },
            Err(error) => violations.push(format!("cannot read {relative}: {error}")),
        }
    }
    violations.extend(audit_files(&files));
    violations
}

pub fn audit_sources(sources: &[(&str, &str)]) -> Vec<String> {
    let mut files = Vec::new();
    let mut violations = Vec::new();
    for (name, source) in sources {
        match syn::parse_file(source) {
            Ok(file) => files.push(((*name).to_owned(), file)),
            Err(error) => violations.push(format!("cannot parse {name}: {error}")),
        }
    }
    violations.extend(audit_files(&files));
    violations
}

fn audit_files(files: &[(String, syn::File)]) -> Vec<String> {
    let mut aliases = Vec::new();
    for (_, file) in files {
        collect_aliases(&file.items, &mut aliases);
    }
    let family = expand_family(files, &aliases, PENDING);
    let mut audit = Audit::new(&family);
    for alias in &aliases {
        if family.contains(&alias.left) && family.contains(&alias.right) {
            audit.violations.push(format!(
                "forbidden {} alias {} -> {}{}",
                alias.kind,
                alias.left,
                alias.right,
                if alias.raw { " (raw identifier)" } else { "" }
            ));
        }
    }
    for (source, file) in files {
        audit_items(&file.items, source, &mut audit);
    }
    let mut violations = audit.finish();
    violations.extend(audit_public_surface(files, &family, &aliases));
    violations
}

struct Audit<'a> {
    family: &'a BTreeSet<String>,
    declarations: usize,
    methods: BTreeMap<String, usize>,
    expected: BTreeMap<String, syn::Signature>,
    violations: Vec<String>,
}

impl<'a> Audit<'a> {
    fn new(family: &'a BTreeSet<String>) -> Self {
        Self {
            family,
            declarations: 0,
            methods: BTreeMap::new(),
            expected: expected_signatures(),
            violations: Vec::new(),
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.declarations != 1 {
            self.violations.push(format!(
                "expected one direct public {PENDING} struct, found {}",
                self.declarations
            ));
        }
        for name in self.expected.keys() {
            if self.methods.get(name) != Some(&1) {
                self.violations
                    .push(format!("expected one exact public {name} method"));
            }
        }
        self.violations
    }
}

fn audit_items(items: &[Item], source: &str, audit: &mut Audit<'_>) {
    for item in items {
        if source == "pending.rs" && !allowed_defining_item(item) {
            audit.violations.push(
                "pending.rs: defining module contains an item outside the closed carrier"
                    .to_owned(),
            );
        }
        match item {
            Item::Struct(item) if ident_name(&item.ident) == PENDING => {
                audit.declarations += 1;
                if ident_is_raw(&item.ident) || !matches!(item.vis, Visibility::Public(_)) {
                    audit.violations.push(format!(
                        "{source}: pending carrier must be a direct public struct"
                    ));
                }
                if matches!(item.fields, Fields::Unit)
                    || item
                        .fields
                        .iter()
                        .any(|field| !matches!(field.vis, Visibility::Inherited))
                {
                    audit.violations.push(format!(
                        "{source}: pending carrier fields must be private and non-unit"
                    ));
                }
                if item
                    .attrs
                    .iter()
                    .any(|attribute| !attribute.path().is_ident("doc"))
                {
                    audit.violations.push(format!(
                        "{source}: pending carrier has an unreviewed attribute"
                    ));
                }
                if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
                    audit.violations.push(format!(
                        "{source}: pending carrier declaration cannot be generic"
                    ));
                }
            }
            Item::Impl(item) if exact_admission_impl(item, source) => {}
            Item::Impl(item) => audit_impl(item, source, audit),
            Item::Macro(_) | Item::Verbatim(_) => audit
                .violations
                .push(format!("{source}: unexpanded module item is forbidden")),
            Item::Mod(item) => {
                if item.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("path") || attribute.path().is_ident("cfg_attr")
                }) {
                    audit
                        .violations
                        .push(format!("{source}: path-substituted module is forbidden"));
                }
                if let Some((_, nested)) = &item.content {
                    audit_items(nested, source, audit);
                }
            }
            _ => {}
        }
    }
}

fn allowed_defining_item(item: &Item) -> bool {
    match item {
        Item::Use(item) => matches!(item.vis, Visibility::Inherited),
        Item::Struct(item) => ident_name(&item.ident) == PENDING,
        Item::Impl(item) => {
            item.trait_.is_none()
                && type_name(&item.self_ty).is_some_and(|(name, raw)| name == PENDING && !raw)
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.len() == 1)
        }
        _ => false,
    }
}

fn audit_impl(item: &syn::ItemImpl, source: &str, audit: &mut Audit<'_>) {
    let Some((target, raw)) = type_name(&item.self_ty) else {
        return;
    };
    if !audit.family.contains(&target) {
        return;
    }
    if raw {
        audit
            .violations
            .push(format!("{source}: raw pending carrier identifier"));
    }
    if item
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        audit.violations.push(format!(
            "{source}: pending impl has an unreviewed attribute"
        ));
    }
    if item.trait_.is_some() {
        audit
            .violations
            .push(format!("{source}: trait impl for pending carrier or alias"));
        return;
    }
    for member in &item.items {
        match member {
            ImplItem::Fn(method) => audit_method(method, source, audit),
            ImplItem::Const(item) if !matches!(item.vis, Visibility::Inherited) => audit
                .violations
                .push(format!("{source}: visible pending associated const")),
            ImplItem::Type(item) if !matches!(item.vis, Visibility::Inherited) => audit
                .violations
                .push(format!("{source}: visible pending associated type")),
            ImplItem::Macro(_) | ImplItem::Verbatim(_) => audit.violations.push(format!(
                "{source}: pending impl contains uninspectable tokens"
            )),
            _ => {}
        }
    }
}

fn audit_method(method: &ImplItemFn, source: &str, audit: &mut Audit<'_>) {
    if matches!(method.vis, Visibility::Inherited) {
        return;
    }
    let name = ident_name(&method.sig.ident);
    *audit.methods.entry(name.clone()).or_default() += 1;
    let exact = matches!(method.vis, Visibility::Public(_))
        && !ident_is_raw(&method.sig.ident)
        && method
            .attrs
            .iter()
            .all(|attribute| attribute.path().is_ident("doc"))
        && audit
            .expected
            .get(&name)
            .is_some_and(|expected| signatures_match(&method.sig, expected));
    if !exact {
        audit
            .violations
            .push(format!("{source}: non-exact visible pending method {name}"));
    }
}

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

fn expected_signatures() -> BTreeMap<String, syn::Signature> {
    [
        "pub fn from_admitted_frame(bytes: Vec<u8>) -> Result<Self, QualificationFaultError> {}",
        "pub fn verify_and_consume(self, verifier: &mut crate::QualificationFaultVerifier, context: &QualificationFaultContext, now_unix_seconds: u64) -> Result<VerifiedQualificationFault, QualificationFaultError> {}",
        "pub fn encode_relay(self, codec: &crate::QualificationFaultRelayCodecV1, binding: &runne_api::QualificationFaultRelayBindingV1) -> Result<Vec<u8>, crate::QualificationFaultRelayError> {}",
    ]
    .into_iter()
    .map(|source| {
        let method = syn::parse_str::<ImplItemFn>(source).expect("valid reviewed signature");
        (ident_name(&method.sig.ident), method.sig)
    })
    .collect()
}

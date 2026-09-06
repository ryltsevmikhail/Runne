use std::fs;
use std::path::Path;

use syn::{Fields, ImplItem, Item, ReturnType, Type, Visibility};

use crate::authority_use_audit;

const VERIFIED: &str = "VerifiedQualificationRunContext";
const ADMISSION: &str = "PendingQualificationAdmission";
const VERIFIER: &str = "QualificationRunContextVerifier";
const PENDING_CONTEXT: &str = "PendingQualificationRunContext";
const RELAY_PAIR: &str = "QualificationAdmissionRelayPair";
const CONTEXT_CODEC: &str = "QualificationRunContextRelayCodecV1";

pub fn audit_crate(root: &Path) -> Vec<String> {
    let mut sources = Vec::new();
    collect(root, &mut sources);
    let owned: Vec<(String, String)> = sources
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            (name, fs::read_to_string(path).expect("read Rust source"))
        })
        .collect();
    audit_sources(
        &owned
            .iter()
            .map(|(n, s)| (n.as_str(), s.as_str()))
            .collect::<Vec<_>>(),
    )
}

pub fn audit_sources(sources: &[(&str, &str)]) -> Vec<String> {
    let mut audit = Audit::default();
    for (source, text) in sources {
        match syn::parse_file(text) {
            Ok(file) => audit.items(&file.items, source, 0),
            Err(error) => audit.violations.push(format!("{source}: parse: {error}")),
        }
    }
    for name in [
        VERIFIED,
        ADMISSION,
        VERIFIER,
        PENDING_CONTEXT,
        RELAY_PAIR,
        CONTEXT_CODEC,
    ] {
        if audit
            .declarations
            .iter()
            .filter(|found| found.as_str() == name)
            .count()
            != 1
        {
            audit
                .violations
                .push(format!("expected one direct {name} declaration"));
        }
    }
    audit.violations
}

fn collect(root: &Path, paths: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root).expect("read source tree") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
}

#[derive(Default)]
struct Audit {
    declarations: Vec<String>,
    violations: Vec<String>,
}

impl Audit {
    fn items(&mut self, items: &[Item], source: &str, depth: usize) {
        for item in items {
            self.item(item, source, depth);
        }
    }

    fn item(&mut self, item: &Item, source: &str, depth: usize) {
        match item {
            Item::Struct(item) if guarded(&item.ident.to_string()) => {
                let name = item.ident.to_string();
                self.declarations.push(name.clone());
                if !matches!(item.vis, Visibility::Public(_))
                    || matches!(item.fields, Fields::Unit)
                    || item
                        .fields
                        .iter()
                        .any(|field| !matches!(field.vis, Visibility::Inherited))
                    || item.attrs.iter().any(|attr| !attr.path().is_ident("doc"))
                {
                    self.violations
                        .push(format!("{source}: unsafe {name} declaration"));
                }
            }
            Item::Impl(item) if type_name(&item.self_ty).as_deref().is_some_and(guarded) => {
                let owner = type_name(&item.self_ty).expect("guarded owner");
                if item.trait_.is_some() {
                    self.violations
                        .push(format!("{source}: trait impl for {owner}"));
                } else {
                    for member in &item.items {
                        match member {
                            ImplItem::Fn(method) if matches!(method.vis, Visibility::Public(_)) => {
                                self.check_method(&owner, method, source);
                            }
                            ImplItem::Const(value)
                                if !matches!(value.vis, Visibility::Inherited) =>
                            {
                                self.violations
                                    .push(format!("{source}: visible const on {owner}"));
                            }
                            ImplItem::Type(value)
                                if !matches!(value.vis, Visibility::Inherited) =>
                            {
                                self.violations
                                    .push(format!("{source}: visible type on {owner}"));
                            }
                            ImplItem::Macro(_) | ImplItem::Verbatim(_) => self
                                .violations
                                .push(format!("{source}: opaque item on {owner}")),
                            _ => {}
                        }
                    }
                }
            }
            Item::Type(item) if mentions(&item.ty) => self
                .violations
                .push(format!("{source}: alias involving guarded authority")),
            Item::Struct(item)
                if !guarded(&item.ident.to_string())
                    && item.fields.iter().any(|field| mentions(&field.ty))
                    && matches!(item.vis, Visibility::Public(_)) =>
            {
                self.violations
                    .push(format!("{source}: public wrapper around guarded authority"));
            }
            Item::Enum(item)
                if matches!(item.vis, Visibility::Public(_))
                    && item
                        .variants
                        .iter()
                        .flat_map(|variant| variant.fields.iter())
                        .any(|field| mentions(&field.ty)) =>
            {
                self.violations.push(format!(
                    "{source}: public enum wrapper around guarded authority"
                ));
            }
            Item::Fn(item)
                if matches!(item.vis, Visibility::Public(_)) && signature_mentions(&item.sig) =>
            {
                self.violations.push(format!(
                    "{source}: public free function exposes guarded authority"
                ));
            }
            Item::Use(item) => {
                if let Some(violation) = authority_use_audit::violation(item, source, depth) {
                    self.violations.push(violation);
                }
            }
            Item::Mod(item) => {
                if item
                    .attrs
                    .iter()
                    .any(|attr| attr.path().is_ident("path") || attr.path().is_ident("cfg_attr"))
                {
                    self.violations
                        .push(format!("{source}: path-substituted module"));
                }
                if let Some((_, nested)) = &item.content {
                    self.items(nested, source, depth + 1);
                }
            }
            Item::Macro(_) | Item::Verbatim(_) => self
                .violations
                .push(format!("{source}: opaque module item")),
            _ => {}
        }
    }

    fn check_method(&mut self, owner: &str, method: &syn::ImplItemFn, source: &str) {
        let name = method.sig.ident.to_string();
        let allowed = expected_signature(owner, &name)
            .is_some_and(|expected| signatures_match(&method.sig, &expected));
        let exact_ordered_output = owner == RELAY_PAIR && name == "into_ordered_frames";
        if !allowed
            || !matches!(method.vis, Visibility::Public(_))
            || (returns_raw(&method.sig.output) && !exact_ordered_output)
        {
            self.violations
                .push(format!("{source}: forbidden visible {owner}::{name}"));
        }
    }
}

fn expected_signature(owner: &str, method: &str) -> Option<syn::Signature> {
    let source = match (owner, method) {
        (VERIFIED, "context_id") => "pub const fn context_id(&self) -> [u8; 32] {}",
        (VERIFIED, "nonce") => "pub const fn nonce(&self) -> [u8; 32] {}",
        (VERIFIED, "expires_at") => "pub const fn expires_at(&self) -> u64 {}",
        (VERIFIED, "ticket_sha256") => "pub const fn ticket_sha256(&self) -> [u8; 32] {}",
        (ADMISSION, "from_admitted_bundle") => {
            "pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> {}"
        }
        (ADMISSION, "encode_relays") => {
            "pub fn encode_relays(self, context_codec: &crate::QualificationRunContextRelayCodecV1, context_binding: &runne_api::QualificationRunContextRelayBindingV1, fault_codec: &crate::QualificationFaultRelayCodecV1, fault_binding: &runne_api::QualificationFaultRelayBindingV1) -> Result<QualificationAdmissionRelayPair, QualificationAdmissionRelayError> {}"
        }
        (VERIFIER, "from_compiled_policy") => "pub fn from_compiled_policy() -> Self {}",
        (VERIFIER, "verify_and_consume") => {
            "pub fn verify_and_consume(&mut self, bytes: &[u8], expected: &QualificationRunContextExpectation, now_unix_seconds: u64) -> Result<VerifiedQualificationRunContext, QualificationRunContextError> {}"
        }
        (RELAY_PAIR, "into_ordered_frames") => {
            "pub fn into_ordered_frames(self) -> [Vec<u8>; 2] {}"
        }
        (CONTEXT_CODEC, "from_protected_activation") => {
            "pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self {}"
        }
        (CONTEXT_CODEC, "recognizes_frame") => "pub fn recognizes_frame(frame: &[u8]) -> bool {}",
        (CONTEXT_CODEC, "decode") => {
            "pub fn decode(&self, frame: &[u8], expected: &QualificationRunContextRelayBindingV1) -> Result<PendingQualificationRunContext, QualificationRunContextRelayError> {}"
        }
        _ => return None,
    };
    syn::parse_str::<syn::ImplItemFn>(source)
        .ok()
        .map(|item| item.sig)
}

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

fn guarded(name: &str) -> bool {
    matches!(
        name,
        VERIFIED | ADMISSION | VERIFIER | PENDING_CONTEXT | RELAY_PAIR | CONTEXT_CODEC
    )
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => {
            path.path.segments.last().map(|s| s.ident.to_string())
        }
        _ => None,
    }
}

fn mentions(ty: &Type) -> bool {
    let text = format!("{ty:?}");
    [
        VERIFIED,
        ADMISSION,
        VERIFIER,
        PENDING_CONTEXT,
        RELAY_PAIR,
        CONTEXT_CODEC,
    ]
    .iter()
    .any(|name| {
        text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| word == *name)
    })
}

fn signature_mentions(sig: &syn::Signature) -> bool {
    sig.inputs.iter().any(|arg| match arg {
        syn::FnArg::Typed(arg) => mentions(&arg.ty),
        syn::FnArg::Receiver(_) => false,
    }) || matches!(&sig.output, ReturnType::Type(_, ty) if mentions(ty))
}

fn returns_raw(output: &ReturnType) -> bool {
    matches!(output, ReturnType::Type(_, ty) if {
        let text = format!("{ty:?}");
        text.contains("Vec") && text.contains("u8") || text.contains("Slice") && text.contains("u8") || text.contains("String")
    })
}

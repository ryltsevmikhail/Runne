use syn::{Fields, Type, UseTree, Visibility};

use crate::pending_surface_aliases::{ident_is_raw, ident_name, type_name};

const PENDING: &str = "PendingQualificationFault";
const CODEC: &str = "QualificationFaultRelayCodecV1";
const ADMISSION: &str = "PendingQualificationAdmission";
const ADMISSION_CODEC: &str = "QualificationAdmissionRelayCodecV1";

pub fn exact_relay_decode(owner: &syn::ItemImpl, method: &syn::ImplItemFn, source: &str) -> bool {
    let owner_is_codec = type_name(&owner.self_ty).is_some_and(|(name, raw)| {
        name == CODEC
            && !raw
            && matches!(&*owner.self_ty, Type::Path(path) if path.path.segments.len() == 1)
    });
    let expected = syn::parse_str::<syn::ImplItemFn>(
        "pub fn decode(&self, frame: &[u8], expected: &QualificationFaultRelayBindingV1) -> Result<Option<PendingQualificationFault>, QualificationFaultRelayError> {}",
    )
    .expect("valid reviewed relay decode signature");
    source == "relay.rs"
        && owner.trait_.is_none()
        && owner_is_codec
        && owner.generics.params.is_empty()
        && owner.generics.where_clause.is_none()
        && owner
            .attrs
            .iter()
            .all(|attribute| attribute.path().is_ident("doc"))
        && matches!(method.vis, Visibility::Public(_))
        && method
            .attrs
            .iter()
            .all(|attribute| attribute.path().is_ident("doc"))
        && signatures_match(&method.sig, &expected.sig)
}

pub fn exact_reexport(item: &syn::ItemUse, source: &str) -> bool {
    matches!(
        &item.tree,
        UseTree::Path(path)
            if ident_name(&path.ident) == "pending"
                && !ident_is_raw(&path.ident)
                && matches!(&*path.tree, UseTree::Name(name) if ident_name(&name.ident) == PENDING && !ident_is_raw(&name.ident))
    ) && source == "lib.rs"
        && matches!(item.vis, Visibility::Public(_))
        && item.attrs.is_empty()
}

pub fn exact_admission_struct(item: &syn::ItemStruct, source: &str) -> bool {
    let Fields::Named(fields) = &item.fields else {
        return false;
    };
    let observed = fields
        .named
        .iter()
        .map(|field| {
            (
                field.ident.as_ref().map(ident_name),
                type_name(&field.ty),
                matches!(field.vis, Visibility::Inherited),
            )
        })
        .collect::<Vec<_>>();
    source == "admission.rs"
        && ident_name(&item.ident) == ADMISSION
        && !ident_is_raw(&item.ident)
        && matches!(item.vis, Visibility::Public(_))
        && item.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && item.generics.params.is_empty()
        && item.generics.where_clause.is_none()
        && observed
            == [
                (
                    Some("context".to_owned()),
                    Some(("PendingQualificationRunContext".to_owned(), false)),
                    true,
                ),
                (
                    Some("fault".to_owned()),
                    Some((PENDING.to_owned(), false)),
                    true,
                ),
            ]
}

pub fn exact_admission_impl(item: &syn::ItemImpl, source: &str) -> bool {
    let owner = type_name(&item.self_ty);
    let constructor = syn::parse_str::<syn::ImplItemFn>(
        "pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> {}",
    )
    .expect("valid admission signature");
    let relay = syn::parse_str::<syn::ImplItemFn>(
        "pub fn encode_relay_transcript(self, codec: &QualificationAdmissionRelayCodecV1, context_binding: &runne_api::QualificationRunContextRelayBindingV1, fault_binding: &runne_api::QualificationFaultRelayBindingV1) -> Result<QualificationAdmissionRelayTranscript, QualificationAdmissionRelayError> {}",
    )
    .expect("valid admission relay signature");
    let retained = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn from_relay_members(context: PendingQualificationRunContext, fault: PendingQualificationFault) -> Result<Self, QualificationAdmissionRelayError> {}",
    )
    .expect("valid retained admission signature");
    let verification = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn verify_exact_borrowed(&self, context_verifier: &mut crate::QualificationRunContextVerifier, fault_verifier: &mut crate::QualificationFaultVerifier, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(), crate::QualificationAdmissionVerificationError> {}",
    )
    .expect("valid admission verification signature");
    let fence_verification = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn verify_exact_for_fence_borrowed(&self, context_verifier: &mut crate::QualificationRunContextVerifier, fault_verifier: &mut crate::QualificationFaultVerifier, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<crate::VerifiedQualificationFenceFacts, crate::QualificationAdmissionVerificationError,> {}",
    )
    .expect("valid admission fence verification signature");
    source == "admission.rs"
        && item.trait_.is_none()
        && owner.is_some_and(|(name, raw)| name == ADMISSION && !raw)
        && matches!(&*item.self_ty, Type::Path(path) if path.path.segments.len() == 1)
        && item.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && item.generics.params.is_empty()
        && item.generics.where_clause.is_none()
        && matches!(item.items.len(), 1 | 3 | 4 | 5)
        && item.items.iter().all(|member| {
            matches!(member, syn::ImplItem::Fn(method)
            if method.attrs.iter().all(|attr| attr.path().is_ident("doc"))
                && (signatures_match(&method.sig, &constructor.sig)
                    || signatures_match(&method.sig, &relay.sig)
                    || signatures_match(&method.sig, &retained.sig)
                    || signatures_match(&method.sig, &verification.sig)
                    || signatures_match(&method.sig, &fence_verification.sig)))
        })
        && item
            .items
            .iter()
            .filter(|member| {
                matches!(member, syn::ImplItem::Fn(method)
            if signatures_match(&method.sig, &constructor.sig))
            })
            .count()
            == 1
}

pub fn exact_admission_relay_method(
    owner: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    source: &str,
) -> bool {
    let owner_type = type_name(&owner.self_ty);
    let owner_is_codec = owner_type.as_ref().is_some_and(|(name, raw)| {
        name == ADMISSION_CODEC
            && !raw
            && matches!(&*owner.self_ty, Type::Path(path) if path.path.segments.len() == 1)
    });
    let owner_is_context = owner_type.as_ref().is_some_and(|(name, raw)| {
        name == "PendingQualificationRunContext"
            && !raw
            && matches!(&*owner.self_ty, Type::Path(path) if path.path.segments.len() == 1)
    });
    let encode = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn encode(&self, context: PendingQualificationRunContext, fault: PendingQualificationFault, context_binding: &QualificationRunContextRelayBindingV1, fault_binding: &QualificationFaultRelayBindingV1) -> Result<QualificationAdmissionRelayTranscript, QualificationAdmissionRelayError> {}",
    )
    .expect("valid reviewed admission relay encode");
    let decode = syn::parse_str::<syn::ImplItemFn>(
        "pub fn decode_transcript(&self, bytes: &[u8], context_binding: &QualificationRunContextRelayBindingV1, fault_binding: &QualificationFaultRelayBindingV1) -> Result<PendingQualificationAdmission, QualificationAdmissionRelayError> {}",
    )
    .expect("valid reviewed admission relay decode");
    let relation = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn matches_fault(&self, fault: &crate::PendingQualificationFault) -> bool {}",
    )
    .expect("valid reviewed admission relation");
    let context_verification = syn::parse_str::<syn::ImplItemFn>(
        "pub(crate) fn verify_installed_borrowed(&self, verifier: &mut crate::QualificationRunContextVerifier, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(crate::VerifiedQualificationRunContext, crate::QualificationFaultContext), crate::QualificationRunContextError> {}",
    )
    .expect("valid reviewed context verification");
    owner.trait_.is_none()
        && ((source == "admission_relay_codec.rs" && owner_is_codec)
            || (source == "pending_context.rs" && owner_is_context))
        && owner.generics.params.is_empty()
        && owner.generics.where_clause.is_none()
        && owner.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && method.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && (signatures_match(&method.sig, &encode.sig)
            || signatures_match(&method.sig, &decode.sig)
            || signatures_match(&method.sig, &relation.sig)
            || signatures_match(&method.sig, &context_verification.sig))
}

pub fn exact_combined_verification_method(
    owner: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    source: &str,
) -> bool {
    let admission = syn::parse_str::<syn::ImplItemFn>(
        "pub fn verify_exact_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(), QualificationAdmissionVerificationError> {}",
    )
    .expect("valid combined verification signature");
    let fence = syn::parse_str::<syn::ImplItemFn>(
        "pub fn verify_exact_for_fence_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<crate::VerifiedQualificationFenceFacts, QualificationAdmissionVerificationError> {}",
    )
    .expect("valid combined fence verification signature");
    source == "admission_verification.rs"
        && owner.trait_.is_none()
        && type_name(&owner.self_ty)
            .is_some_and(|(name, raw)| name == "QualificationAdmissionVerifier" && !raw)
        && owner.generics.params.is_empty()
        && owner.generics.where_clause.is_none()
        && (signatures_match(&method.sig, &admission.sig)
            || signatures_match(&method.sig, &fence.sig))
}

pub fn exact_admission_reexport(item: &syn::ItemUse, source: &str) -> bool {
    let UseTree::Path(path) = &item.tree else {
        return false;
    };
    let UseTree::Group(group) = &*path.tree else {
        return false;
    };
    let names = group
        .items
        .iter()
        .filter_map(|tree| match tree {
            UseTree::Name(name) if !ident_is_raw(&name.ident) => Some(ident_name(&name.ident)),
            _ => None,
        })
        .collect::<Vec<_>>();
    source == "lib.rs"
        && ident_name(&path.ident) == "admission"
        && !ident_is_raw(&path.ident)
        && matches!(item.vis, Visibility::Public(_))
        && item.attrs.is_empty()
        && names.len() == group.items.len()
        && names
            == [
                ADMISSION.to_owned(),
                "QualificationAdmissionError".to_owned(),
            ]
}

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

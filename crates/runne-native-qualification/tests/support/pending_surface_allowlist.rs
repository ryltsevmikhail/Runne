use syn::{Fields, Type, UseTree, Visibility};

use crate::pending_surface_aliases::{ident_is_raw, ident_name, type_name};

const PENDING: &str = "PendingQualificationFault";
const CODEC: &str = "QualificationFaultRelayCodecV1";
const ADMISSION: &str = "PendingQualificationAdmission";

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
                    Some("_context".to_owned()),
                    Some(("PendingQualificationRunContext".to_owned(), false)),
                    true,
                ),
                (
                    Some("_fault".to_owned()),
                    Some((PENDING.to_owned(), false)),
                    true,
                ),
            ]
}

pub fn exact_admission_impl(item: &syn::ItemImpl, source: &str) -> bool {
    let owner = type_name(&item.self_ty);
    let expected = syn::parse_str::<syn::ImplItemFn>(
        "pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> {}",
    )
    .expect("valid admission signature");
    source == "admission.rs"
        && item.trait_.is_none()
        && owner.is_some_and(|(name, raw)| name == ADMISSION && !raw)
        && matches!(&*item.self_ty, Type::Path(path) if path.path.segments.len() == 1)
        && item.attrs.iter().all(|attr| attr.path().is_ident("doc"))
        && item.generics.params.is_empty()
        && item.generics.where_clause.is_none()
        && item.items.len() == 1
        && matches!(&item.items[0], syn::ImplItem::Fn(method)
            if matches!(method.vis, Visibility::Public(_))
                && method.attrs.iter().all(|attr| attr.path().is_ident("doc"))
                && signatures_match(&method.sig, &expected.sig))
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

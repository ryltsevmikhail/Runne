use syn::{Type, UseTree, Visibility};

use crate::pending_surface_aliases::{ident_is_raw, ident_name, type_name};

const PENDING: &str = "PendingQualificationFault";
const CODEC: &str = "QualificationFaultRelayCodecV1";

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

fn signatures_match(actual: &syn::Signature, expected: &syn::Signature) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual.inputs.pop_punct();
    expected.inputs.pop_punct();
    actual == expected
}

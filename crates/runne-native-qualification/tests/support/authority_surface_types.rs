use syn::visit::{self, Visit};
use syn::{Type, Visibility};

use crate::authority_surface_expected::SENSITIVE;

pub const fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

pub fn is_raw(ident: &syn::Ident) -> bool {
    ident.to_string().starts_with("r#")
}

pub fn plain_ident(ident: &syn::Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_owned()
}

pub fn sensitive_ident(ident: &syn::Ident) -> bool {
    SENSITIVE.contains(&plain_ident(ident).as_str())
}

pub fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| plain_ident(&segment.ident)),
        _ => None,
    }
}

pub fn type_mentions(ty: &Type) -> bool {
    node_mentions(ty)
}

pub fn signature_mentions(signature: &syn::Signature) -> bool {
    node_mentions(signature)
}

pub fn node_mentions<'ast, T>(node: &'ast T) -> bool
where
    T: VisitNode<'ast>,
{
    let mut visitor = SensitiveVisitor(false);
    node.visit_with(&mut visitor);
    visitor.0
}

pub trait VisitNode<'ast> {
    fn visit_with(&'ast self, visitor: &mut SensitiveVisitor);
}

macro_rules! visit_node {
    ($type:ty, $method:ident) => {
        impl<'ast> VisitNode<'ast> for $type {
            fn visit_with(&'ast self, visitor: &mut SensitiveVisitor) {
                visitor.$method(self);
            }
        }
    };
}

visit_node!(Type, visit_type);
visit_node!(syn::Signature, visit_signature);
visit_node!(syn::ItemTrait, visit_item_trait);
visit_node!(syn::ItemTraitAlias, visit_item_trait_alias);
visit_node!(syn::ItemForeignMod, visit_item_foreign_mod);
visit_node!(syn::Path, visit_path);
visit_node!(syn::Generics, visit_generics);

pub struct SensitiveVisitor(bool);

impl<'ast> Visit<'ast> for SensitiveVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .iter()
            .any(|segment| SENSITIVE.contains(&plain_ident(&segment.ident).as_str()))
        {
            self.0 = true;
        }
        visit::visit_path(self, path);
    }
}

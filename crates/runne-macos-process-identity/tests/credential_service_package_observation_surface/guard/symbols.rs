use std::collections::BTreeMap;

use super::source_model::{
    BodyId, ModuleId, PackageId, ScopeId, SourceId, SyntaxId, TargetId, TypeDefId, ValueDefId,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum MemberKey {
    Named(String),
    Unnamed(u32),
}

#[derive(Clone)]
pub(super) struct FieldRecord {
    pub(super) member: MemberKey,
    pub(super) ty: syn::Type,
}

#[derive(Clone)]
pub(super) struct VariantRecord {
    pub(super) fields: Vec<FieldRecord>,
}

#[derive(Clone)]
pub(super) enum TypeKind {
    CanonicalTarget,
    Struct(Vec<FieldRecord>),
    Enum(Vec<VariantRecord>),
    Union(Vec<FieldRecord>),
    Alias(Box<syn::Type>),
}

#[derive(Clone)]
pub(super) struct TypeRecord {
    pub(super) id: TypeDefId,
    pub(super) name: String,
    pub(super) scope: ScopeId,
    pub(super) source: SourceId,
    pub(super) kind: TypeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CanonicalMethod {
    Capture,
    Verify,
}

#[derive(Clone)]
pub(super) enum ValueKind {
    Function { body: Option<BodyId> },
    Const { ty: syn::Type },
    Static { ty: syn::Type },
}

#[derive(Clone)]
pub(super) struct ValueRecord {
    pub(super) id: ValueDefId,
    pub(super) name: String,
    pub(super) scope: ScopeId,
    pub(super) owner: Option<TypeDefId>,
    pub(super) canonical_method: Option<CanonicalMethod>,
    pub(super) kind: ValueKind,
}

#[derive(Clone)]
pub(super) enum BodySyntax {
    Function {
        signature: Box<syn::Signature>,
        block: syn::Block,
        self_type: Option<syn::Type>,
    },
    Initializer {
        expression: syn::Expr,
    },
}

#[derive(Clone)]
pub(super) struct BodyRecord {
    pub(super) id: BodyId,
    pub(super) owner: ValueDefId,
    pub(super) scope: ScopeId,
    pub(super) source: SourceId,
    pub(super) syntax: SyntaxId,
    pub(super) syntax_tree: Box<BodySyntax>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SyntaxContext {
    pub(super) syntax: SyntaxId,
    pub(super) scope: ScopeId,
}

#[derive(Clone, Debug)]
pub(super) struct ModuleRecord {
    pub(super) id: ModuleId,
    pub(super) package: PackageId,
    pub(super) target: TargetId,
    pub(super) scope: ScopeId,
    pub(super) source: SourceId,
    pub(super) path: Vec<String>,
    pub(super) parent: Option<ScopeId>,
    pub(super) children: BTreeMap<String, ScopeId>,
}

pub(super) fn fields(fields: &syn::Fields) -> Vec<FieldRecord> {
    fields
        .iter()
        .enumerate()
        .map(|(ordinal, field)| FieldRecord {
            member: field.ident.as_ref().map_or_else(
                || MemberKey::Unnamed(u32::try_from(ordinal).expect("field count exceeds u32")),
                |name| MemberKey::Named(name.to_string()),
            ),
            ty: field.ty.clone(),
        })
        .collect()
}

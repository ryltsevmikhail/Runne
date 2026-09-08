use super::semantic_index::{IndexedItem, Resolution};
use super::semantic_index_build::Builder;
use super::source_model::{BodyId, Namespace, TypeDefId, ValueDefId};
use super::symbols::{BodyRecord, BodySyntax, CanonicalMethod, TypeKind, ValueKind, ValueRecord};

pub(super) fn collect_values(builder: &mut Builder<'_>) {
    let items = builder.items.clone();
    for indexed in &items {
        collect_value(builder, indexed);
    }
}

fn collect_value(builder: &mut Builder<'_>, indexed: &IndexedItem) {
    match &indexed.item {
        syn::Item::Fn(item) => add_function(builder, indexed, &item.sig, &item.block, None),
        syn::Item::Const(item) => {
            add_initializer(builder, indexed, &item.ident, &item.ty, &item.expr, false);
        }
        syn::Item::Static(item) => {
            add_initializer(builder, indexed, &item.ident, &item.ty, &item.expr, true);
        }
        syn::Item::Impl(item) => add_impl(builder, indexed, item),
        _ => {}
    }
}

fn add_impl(builder: &mut Builder<'_>, indexed: &IndexedItem, item: &syn::ItemImpl) {
    let owner = type_path(&item.self_ty).and_then(|path| {
        match super::semantic_index_resolve::resolve_type_parts(
            &builder.modules,
            &builder.types,
            &builder.imports,
            indexed.scope,
            &path,
        ) {
            Resolution::Exact(id) => Some(id),
            _ => None,
        }
    });
    for impl_item in &item.items {
        if let syn::ImplItem::Fn(method) = impl_item
            && super::cfg_projection::is_production(&method.attrs)
        {
            let nested = IndexedItem {
                source: indexed.source,
                syntax: builder.syntax(),
                scope: indexed.scope,
                item: indexed.item.clone(),
            };
            add_function(builder, &nested, &method.sig, &method.block, owner);
        }
    }
}

fn add_function(
    builder: &mut Builder<'_>,
    indexed: &IndexedItem,
    signature: &syn::Signature,
    block: &syn::Block,
    owner: Option<TypeDefId>,
) {
    let body = BodyId(u32::try_from(builder.bodies.len()).expect("body count exceeds u32"));
    let id = ValueDefId(builder.def_id(indexed.scope, Namespace::Value, indexed.syntax));
    builder.values.push(ValueRecord {
        id,
        name: signature.ident.to_string(),
        scope: indexed.scope,
        owner,
        canonical_method: owner.and_then(|id| canonical_method(builder, id, &signature.ident)),
        kind: ValueKind::Function { body: Some(body) },
    });
    builder.bodies.push(BodyRecord {
        id: body,
        owner: id,
        scope: indexed.scope,
        source: indexed.source,
        syntax: indexed.syntax,
        syntax_tree: Box::new(BodySyntax::Function {
            signature: Box::new(signature.clone()),
            block: block.clone(),
            self_type: owner.and_then(|id| type_record_type(builder, id)),
        }),
    });
}

fn add_initializer(
    builder: &mut Builder<'_>,
    indexed: &IndexedItem,
    name: &syn::Ident,
    ty: &syn::Type,
    expression: &syn::Expr,
    static_item: bool,
) {
    let body = BodyId(u32::try_from(builder.bodies.len()).expect("body count exceeds u32"));
    let id = ValueDefId(builder.def_id(indexed.scope, Namespace::Value, indexed.syntax));
    let kind = if static_item {
        ValueKind::Static { ty: ty.clone() }
    } else {
        ValueKind::Const { ty: ty.clone() }
    };
    builder.values.push(ValueRecord {
        id,
        name: name.to_string(),
        scope: indexed.scope,
        owner: None,
        canonical_method: None,
        kind,
    });
    builder.bodies.push(BodyRecord {
        id: body,
        owner: id,
        scope: indexed.scope,
        source: indexed.source,
        syntax: indexed.syntax,
        syntax_tree: Box::new(BodySyntax::Initializer {
            expression: expression.clone(),
        }),
    });
}

fn canonical_method(
    builder: &Builder<'_>,
    owner: TypeDefId,
    name: &syn::Ident,
) -> Option<CanonicalMethod> {
    if !matches!(
        builder.types.iter().find(|record| record.id == owner)?.kind,
        TypeKind::CanonicalTarget
    ) {
        return None;
    }
    if name == builder.target.capture_method.as_str() {
        Some(CanonicalMethod::Capture)
    } else if name == builder.target.verify_method.as_str() {
        Some(CanonicalMethod::Verify)
    } else {
        None
    }
}

fn type_record_type(builder: &Builder<'_>, id: TypeDefId) -> Option<syn::Type> {
    builder
        .types
        .iter()
        .find(|record| record.id == id)
        .and_then(|record| syn::parse_str::<syn::Type>(&record.name).ok())
}

fn type_path(ty: &syn::Type) -> Option<Vec<String>> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

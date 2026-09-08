use std::collections::BTreeMap;

use super::provenance::{ShapeFact, UnresolvedReason, ValueFact};
use super::source_model::TypeDefId;
use super::symbols::MemberKey;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Projection {
    Member(MemberKey),
    Index(Option<usize>),
    Dereference,
}

pub(super) fn assignment_projection(expression: &syn::Expr) -> Option<(String, Vec<Projection>)> {
    let mut projection = Vec::new();
    let name = assignment_root(expression, &mut projection)?;
    projection.reverse();
    Some((name, projection))
}

pub(super) fn assign_projected(
    current: &ValueFact,
    projection: &[Projection],
    fact: ValueFact,
) -> ValueFact {
    let Some((head, tail)) = projection.split_first() else {
        return fact;
    };
    match (current, head) {
        (ValueFact::Aggregate(ShapeFact::Reference(inner)), Projection::Dereference) => {
            ValueFact::Aggregate(ShapeFact::Reference(Box::new(assign_projected(
                inner, tail, fact,
            ))))
        }
        (ValueFact::Aggregate(ShapeFact::Record { owner, fields }), Projection::Member(member)) => {
            let mut fields = fields.clone();
            let current = fields.remove(member).unwrap_or(ValueFact::NonTarget);
            fields.insert(member.clone(), assign_projected(&current, tail, fact));
            ValueFact::Aggregate(ShapeFact::Record {
                owner: *owner,
                fields,
            })
        }
        (
            ValueFact::Aggregate(ShapeFact::Tuple { owner, items }),
            Projection::Member(MemberKey::Unnamed(index)),
        ) => update_positional(items, *owner, *index as usize, tail, fact),
        (ValueFact::Aggregate(ShapeFact::Sequence { items }), Projection::Index(Some(index))) => {
            update_positional(items, None, *index, tail, fact)
        }
        (ValueFact::NonTarget, Projection::Member(member)) => {
            ValueFact::Aggregate(ShapeFact::Record {
                owner: None,
                fields: BTreeMap::from([(
                    member.clone(),
                    assign_projected(&ValueFact::NonTarget, tail, fact),
                )]),
            })
        }
        (ValueFact::NonTarget, Projection::Dereference) => {
            ValueFact::Aggregate(ShapeFact::Reference(Box::new(assign_projected(
                &ValueFact::NonTarget,
                tail,
                fact,
            ))))
        }
        _ if fact.may_carry_target() => {
            ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
        }
        _ => current.clone(),
    }
}

fn assignment_root(expression: &syn::Expr, projection: &mut Vec<Projection>) -> Option<String> {
    match expression {
        syn::Expr::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
            Some(path.path.segments[0].ident.to_string())
        }
        syn::Expr::Field(field) => {
            projection.push(Projection::Member(member_key(&field.member)));
            assignment_root(&field.base, projection)
        }
        syn::Expr::Index(index) => {
            projection.push(Projection::Index(super::bodies_support::integer_index(
                &index.index,
            )));
            assignment_root(&index.expr, projection)
        }
        syn::Expr::Unary(value) if matches!(value.op, syn::UnOp::Deref(_)) => {
            projection.push(Projection::Dereference);
            assignment_root(&value.expr, projection)
        }
        syn::Expr::Paren(value) => assignment_root(&value.expr, projection),
        syn::Expr::Group(value) => assignment_root(&value.expr, projection),
        _ => None,
    }
}

fn member_key(member: &syn::Member) -> MemberKey {
    match member {
        syn::Member::Named(name) => MemberKey::Named(name.to_string()),
        syn::Member::Unnamed(index) => MemberKey::Unnamed(index.index),
    }
}

fn update_positional(
    items: &[ValueFact],
    owner: Option<TypeDefId>,
    index: usize,
    tail: &[Projection],
    fact: ValueFact,
) -> ValueFact {
    let Some(length) = index.checked_add(1).filter(|length| *length <= 64) else {
        return ValueFact::MaybeTarget(UnresolvedReason::MissingTargetProvenance);
    };
    let mut updated = items.to_vec();
    updated.resize(length, ValueFact::NonTarget);
    updated[index] = assign_projected(&updated[index], tail, fact);
    match owner {
        Some(owner) => ValueFact::Aggregate(ShapeFact::Tuple {
            owner: Some(owner),
            items: updated,
        }),
        None => ValueFact::Aggregate(ShapeFact::Sequence { items: updated }),
    }
}

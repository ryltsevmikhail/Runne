use std::collections::{BTreeMap, BTreeSet};

use super::source_model::TypeDefId;
use super::symbols::MemberKey;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum TargetMethod {
    Capture,
    Verify,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UnresolvedReason {
    AmbiguousResolution,
    DivergentBranch,
    FixedPointLimit,
    MissingTargetProvenance,
    OpaqueSourceMacro,
    UnsupportedMacro,
    MacroRecursionLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ValueFact {
    NonTarget,
    TargetObject(TypeDefId),
    TargetCallable(TargetMethod),
    CallableParameter(u16),
    Callable(CallableFact),
    Aggregate(ShapeFact),
    OpaqueExternal,
    MaybeTarget(UnresolvedReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CallableFact {
    pub(super) output: Box<ValueFact>,
    pub(super) invoked_parameters: BTreeSet<u16>,
    pub(super) parameter_effects: BTreeMap<u16, TargetMethod>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ShapeFact {
    Record {
        owner: Option<TypeDefId>,
        fields: BTreeMap<MemberKey, ValueFact>,
    },
    Tuple {
        owner: Option<TypeDefId>,
        items: Vec<ValueFact>,
    },
    Sequence {
        items: Vec<ValueFact>,
    },
    Reference(Box<ValueFact>),
}

impl ValueFact {
    pub(super) fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::MaybeTarget(reason), _) | (_, Self::MaybeTarget(reason)) => {
                Self::MaybeTarget(reason.clone())
            }
            (Self::Aggregate(left), Self::Aggregate(right)) => left.join(right).map_or(
                Self::MaybeTarget(UnresolvedReason::DivergentBranch),
                Self::Aggregate,
            ),
            (Self::NonTarget, Self::NonTarget) => Self::NonTarget,
            (Self::OpaqueExternal, Self::OpaqueExternal | Self::NonTarget)
            | (Self::NonTarget, Self::OpaqueExternal) => Self::OpaqueExternal,
            (Self::TargetObject(_), Self::TargetObject(_))
            | (Self::TargetCallable(_), Self::TargetCallable(_))
            | (Self::CallableParameter(_), Self::CallableParameter(_))
            | (Self::Callable(_), Self::Callable(_)) => {
                Self::MaybeTarget(UnresolvedReason::AmbiguousResolution)
            }
            _ => Self::MaybeTarget(UnresolvedReason::DivergentBranch),
        }
    }

    pub(super) fn project_member(&self, member: &MemberKey) -> Self {
        match self.transparent() {
            Self::Aggregate(ShapeFact::Record { fields, .. }) => fields
                .get(member)
                .cloned()
                .unwrap_or_else(|| self.missing_projection()),
            Self::Aggregate(ShapeFact::Tuple { items, .. }) => match member {
                MemberKey::Unnamed(index) => items
                    .get(*index as usize)
                    .cloned()
                    .unwrap_or_else(|| self.missing_projection()),
                MemberKey::Named(_) => self.missing_projection(),
            },
            Self::NonTarget => Self::NonTarget,
            Self::OpaqueExternal => Self::OpaqueExternal,
            Self::MaybeTarget(reason) => Self::MaybeTarget(reason.clone()),
            Self::TargetObject(_)
            | Self::TargetCallable(_)
            | Self::CallableParameter(_)
            | Self::Callable(_)
            | Self::Aggregate(_) => self.missing_projection(),
        }
    }

    pub(super) fn project_index(&self, index: Option<usize>) -> Self {
        match self.transparent() {
            Self::Aggregate(ShapeFact::Tuple { items, .. } | ShapeFact::Sequence { items }) => {
                index.map_or_else(
                    || join_all(items),
                    |index| {
                        items
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| self.missing_projection())
                    },
                )
            }
            Self::NonTarget => Self::NonTarget,
            Self::OpaqueExternal => Self::OpaqueExternal,
            Self::MaybeTarget(reason) => Self::MaybeTarget(reason.clone()),
            Self::TargetObject(_)
            | Self::TargetCallable(_)
            | Self::CallableParameter(_)
            | Self::Callable(_)
            | Self::Aggregate(_) => self.missing_projection(),
        }
    }

    pub(super) fn transparent(&self) -> &Self {
        match self {
            Self::Aggregate(ShapeFact::Reference(inner)) => inner.transparent(),
            other => other,
        }
    }

    pub(super) fn contained_or_self(&self) -> Self {
        match self.transparent() {
            Self::Aggregate(ShapeFact::Tuple { items, .. } | ShapeFact::Sequence { items }) => {
                join_all(items)
            }
            other => other.clone(),
        }
    }

    pub(super) fn may_carry_target(&self) -> bool {
        match self {
            Self::NonTarget | Self::OpaqueExternal => false,
            Self::TargetObject(_)
            | Self::TargetCallable(_)
            | Self::CallableParameter(_)
            | Self::MaybeTarget(_) => true,
            Self::Callable(callable) => callable.output.may_carry_target(),
            Self::Aggregate(shape) => shape.values().any(Self::may_carry_target),
        }
    }

    pub(super) fn positional_len(&self) -> Option<usize> {
        match self.transparent() {
            Self::Aggregate(ShapeFact::Tuple { items, .. } | ShapeFact::Sequence { items }) => {
                Some(items.len())
            }
            _ => None,
        }
    }

    pub(super) fn substitute_parameters(&self, arguments: &[Self]) -> Self {
        match self {
            Self::CallableParameter(parameter) => arguments
                .get(*parameter as usize)
                .cloned()
                .unwrap_or(Self::MaybeTarget(UnresolvedReason::MissingTargetProvenance)),
            Self::Callable(callable) => Self::Callable(CallableFact {
                output: Box::new(callable.output.substitute_parameters(arguments)),
                invoked_parameters: callable.invoked_parameters.clone(),
                parameter_effects: callable.parameter_effects.clone(),
            }),
            Self::Aggregate(shape) => Self::Aggregate(shape.substitute_parameters(arguments)),
            other => other.clone(),
        }
    }

    fn missing_projection(&self) -> Self {
        if self.may_carry_target() {
            Self::MaybeTarget(UnresolvedReason::MissingTargetProvenance)
        } else {
            Self::NonTarget
        }
    }
}

impl ShapeFact {
    fn substitute_parameters(&self, arguments: &[ValueFact]) -> Self {
        match self {
            Self::Record { owner, fields } => Self::Record {
                owner: *owner,
                fields: fields
                    .iter()
                    .map(|(key, fact)| (key.clone(), fact.substitute_parameters(arguments)))
                    .collect(),
            },
            Self::Tuple { owner, items } => Self::Tuple {
                owner: *owner,
                items: items
                    .iter()
                    .map(|fact| fact.substitute_parameters(arguments))
                    .collect(),
            },
            Self::Sequence { items } => Self::Sequence {
                items: items
                    .iter()
                    .map(|fact| fact.substitute_parameters(arguments))
                    .collect(),
            },
            Self::Reference(fact) => {
                Self::Reference(Box::new(fact.substitute_parameters(arguments)))
            }
        }
    }

    fn join(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (
                Self::Record {
                    owner: left_owner,
                    fields: left,
                },
                Self::Record {
                    owner: right_owner,
                    fields: right,
                },
            ) if left_owner == right_owner && left.keys().eq(right.keys()) => Some(Self::Record {
                owner: *left_owner,
                fields: left
                    .iter()
                    .map(|(key, value)| (key.clone(), value.join(&right[key])))
                    .collect(),
            }),
            (
                Self::Tuple {
                    owner: left_owner,
                    items: left,
                },
                Self::Tuple {
                    owner: right_owner,
                    items: right,
                },
            ) if left_owner == right_owner && left.len() == right.len() => Some(Self::Tuple {
                owner: *left_owner,
                items: join_items(left, right),
            }),
            (Self::Sequence { items: left }, Self::Sequence { items: right })
                if left.len() == right.len() =>
            {
                Some(Self::Sequence {
                    items: join_items(left, right),
                })
            }
            (Self::Reference(left), Self::Reference(right)) => {
                Some(Self::Reference(Box::new(left.join(right))))
            }
            _ => None,
        }
    }

    fn values(&self) -> Box<dyn Iterator<Item = &ValueFact> + '_> {
        match self {
            Self::Record { fields, .. } => Box::new(fields.values()),
            Self::Tuple { items, .. } | Self::Sequence { items } => Box::new(items.iter()),
            Self::Reference(value) => Box::new(std::iter::once(value.as_ref())),
        }
    }
}

fn join_items(left: &[ValueFact], right: &[ValueFact]) -> Vec<ValueFact> {
    left.iter()
        .zip(right)
        .map(|(left, right)| left.join(right))
        .collect()
}

fn join_all(items: &[ValueFact]) -> ValueFact {
    items
        .iter()
        .cloned()
        .reduce(|left, right| left.join(&right))
        .unwrap_or(ValueFact::NonTarget)
}

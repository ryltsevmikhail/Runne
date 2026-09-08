use super::super::super::bodies::{BodyEngine, EvaluationMode};
use super::super::super::semantic_index::SemanticIndex;
use super::super::super::source_model::{
    BodyId, DefId, Namespace, PackageId, TargetId, ValueDefId,
};
use super::super::super::symbols::{BodyRecord, BodySyntax};
use super::{ItemMacroContext, MacroFacts, MacroItemEvaluation};

pub(super) fn synthetic_body(context: ItemMacroContext, syntax_tree: BodySyntax) -> BodyRecord {
    let id = DefId {
        package: PackageId(u32::MAX),
        target: TargetId(u32::MAX),
        module: super::super::super::source_model::ModuleId(context.scope.0),
        namespace: Namespace::Value,
        syntax: context.syntax,
    };
    BodyRecord {
        id: BodyId(u32::MAX - context.syntax.0),
        owner: ValueDefId(id),
        scope: context.scope,
        source: context.source,
        syntax: context.syntax,
        syntax_tree: Box::new(syntax_tree),
    }
}

pub(super) fn evaluate_function(
    index: &SemanticIndex,
    context: ItemMacroContext,
    signature: &syn::Signature,
    block: &syn::Block,
    self_type: Option<syn::Type>,
    facts: MacroFacts<'_>,
    result: &mut MacroItemEvaluation,
) {
    let body = synthetic_body(
        context,
        BodySyntax::Function {
            signature: Box::new(signature.clone()),
            block: block.clone(),
            self_type,
        },
    );
    merge_evaluation(index, &body, facts, result);
}

pub(super) fn evaluate_initializer(
    index: &SemanticIndex,
    context: ItemMacroContext,
    expression: &syn::Expr,
    facts: MacroFacts<'_>,
    result: &mut MacroItemEvaluation,
) {
    let body = synthetic_body(
        context,
        BodySyntax::Initializer {
            expression: expression.clone(),
        },
    );
    merge_evaluation(index, &body, facts, result);
}

fn merge_evaluation(
    index: &SemanticIndex,
    body: &BodyRecord,
    facts: MacroFacts<'_>,
    result: &mut MacroItemEvaluation,
) {
    let evaluation = BodyEngine::evaluate(
        index,
        body,
        facts.values,
        facts.functions,
        facts.type_facts,
        EvaluationMode::Analyze,
    );
    result.calls.extend(evaluation.calls);
    result.unresolved.extend(evaluation.unresolved);
}

use super::{
    MacroDefinitions, MacroResolution, ResolvedMacroInvocation, UnresolvedReason, macro_id,
};

impl MacroDefinitions {
    pub(in crate::guard) fn resolve_pattern_expansion(
        &self,
        parent: &ResolvedMacroInvocation,
        invocation: &syn::Macro,
    ) -> MacroResolution {
        let Some(parent_definition) = self
            .items
            .values()
            .flatten()
            .find(|definition| macro_id(definition) == parent.definition)
        else {
            return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
        };
        let Some((scope, name)) = super::super::inventory_macro_scope::macro_path_scope(
            &parent.definition_scope,
            &invocation.path,
        ) else {
            return MacroResolution::Unresolved(UnresolvedReason::MissingDefinition);
        };
        match self.resolve_semantic_definition(
            &parent_definition.source,
            &scope,
            &name,
            parent_definition.source_position,
            invocation.path.segments.len() > 1,
            &mut Vec::new(),
        ) {
            Ok(Some(definition)) => Self::resolve_known_definition(
                definition,
                &invocation.tokens,
                &parent_definition.source,
                &parent.definition_scope,
                parent_definition.source_position,
            ),
            Ok(None) => MacroResolution::Unresolved(UnresolvedReason::MissingDefinition),
            Err(reason) => MacroResolution::Unresolved(reason),
        }
    }
}

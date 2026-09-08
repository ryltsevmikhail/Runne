use super::inventory_macro_rules::{
    ArgumentTemplate, ExpansionTemplate, MacroArm, ResolvedSourceEdge, argument_may_name_source,
    argument_template, arm_forwards_invocation, expansion_templates, resolve_argument,
    selected_arm, substitute_argument,
};
use super::inventory_macro_scope::{
    alias_target_scope, argument_tokens, dependency_exported_definitions, has_exact_local_symbol,
    local_aliases, local_definitions, nearby_external_definitions, select_nearest_alias,
    select_nearest_definition,
};
use std::path::Path;
#[path = "inventory_macro_resolution/model.rs"]
mod model;

pub(super) use model::{
    MacroAlias, MacroDefinition, MacroDefinitions, MacroDependencyKind, MacroInvocation,
    MacroSourceContext,
};

#[derive(Clone, Copy)]
struct MacroSite<'a> {
    source: &'a Path,
    scope: &'a [String],
    source_position: u32,
    exact_scope: bool,
}

impl MacroDefinitions {
    pub(super) fn extend(&mut self, path: &Path, source: &str) {
        super::inventory_macro_collection::collect(path, source, self);
    }

    pub(super) fn resolve(
        &self,
        source: &Path,
        scope: &[String],
        path: &syn::Path,
        tokens: &proc_macro2::TokenStream,
        source_position: u32,
    ) -> Result<Option<Vec<ResolvedSourceEdge>>, String> {
        let Some((target_scope, name)) =
            super::inventory_macro_scope::macro_path_scope(scope, path)
        else {
            return Ok(None);
        };
        let exact_scope = path.segments.len() > 1;
        let resolved = self.resolve_named(
            MacroSite {
                source,
                scope: &target_scope,
                source_position,
                exact_scope,
            },
            &name,
            tokens,
            &mut Vec::new(),
        )?;
        if resolved.is_some() || path.segments.len() < 2 {
            return Ok(resolved);
        }
        let Some(segment) = path.segments.first() else {
            return Ok(None);
        };
        let crate_name = segment.ident.to_string();
        let candidates = dependency_exported_definitions(self, source, &crate_name, &name);
        match candidates.as_slice() {
            [] => Ok(None),
            [definition] => Ok(Some(self.resolve_definition(
                definition,
                tokens,
                &mut Vec::new(),
            )?)),
            _ => panic!("ambiguous exported macro {crate_name}::{name}"),
        }
    }

    pub(super) fn nested_edges(
        &self,
        source: &Path,
        scope: &[String],
        tokens: proc_macro2::TokenStream,
        source_position: u32,
    ) -> Result<Vec<ResolvedSourceEdge>, String> {
        self.resolve_templates(
            source,
            scope,
            &expansion_templates(tokens),
            &ArgumentTemplate::Empty,
            source_position,
            &mut Vec::new(),
        )
    }

    fn resolve_named(
        &self,
        site: MacroSite<'_>,
        name: &str,
        tokens: &proc_macro2::TokenStream,
        stack: &mut Vec<String>,
    ) -> Result<Option<Vec<ResolvedSourceEdge>>, String> {
        let key = format!("{}::{name}", site.scope.join("::"));
        assert!(
            !stack.contains(&key),
            "recursive macro alias or expansion: {key}"
        );
        stack.push(key);
        let local_definitions = local_definitions(
            self,
            site.source,
            site.scope,
            name,
            site.source_position,
            site.exact_scope,
        );
        let local_aliases = local_aliases(
            self,
            site.source,
            site.scope,
            name,
            site.source_position,
            site.exact_scope,
        );
        let result = if !local_definitions.is_empty() {
            let definition = select_nearest_definition(&local_definitions, site.scope);
            assert!(
                local_aliases.iter().all(|alias| {
                    alias_target_scope(&alias.scope, &alias.target)
                        == (definition.scope.clone(), name.to_owned())
                }),
                "ambiguous macro definition and alias: {name}"
            );
            let nearby = nearby_external_definitions(self, site.source, name);
            assert!(
                definition.scope == site.scope || nearby.is_empty(),
                "ambiguous lexical or imported macro definition for {name}"
            );
            Some(self.resolve_definition(definition, tokens, stack)?)
        } else if !local_aliases.is_empty() {
            let alias = select_nearest_alias(&local_aliases);
            self.resolve_alias(alias, tokens, stack)?
        } else {
            let candidates = if site.exact_scope {
                Vec::new()
            } else {
                nearby_external_definitions(self, site.source, name)
            };
            if candidates.is_empty() {
                None
            } else {
                assert_eq!(
                    candidates.len(),
                    1,
                    "ambiguous imported macro definition for {name}"
                );
                Some(self.resolve_definition(candidates[0], tokens, stack)?)
            }
        };
        stack.pop();
        Ok(result)
    }

    fn resolve_definition(
        &self,
        definition: &MacroDefinition,
        tokens: &proc_macro2::TokenStream,
        stack: &mut Vec<String>,
    ) -> Result<Vec<ResolvedSourceEdge>, String> {
        let invocation = argument_template(tokens.clone());
        let arm = selected_arm(&definition.arms, tokens);
        let mut edges = self.resolve_templates(
            &definition.source,
            &definition.scope,
            &arm.templates,
            &invocation,
            definition.source_position,
            stack,
        )?;
        if arm_forwards_invocation(arm) {
            let forwarded = expansion_templates(tokens.clone());
            edges.extend(self.resolve_templates(
                &definition.source,
                &definition.scope,
                &forwarded,
                &ArgumentTemplate::Empty,
                definition.source_position,
                stack,
            )?);
        }
        Ok(edges)
    }

    fn resolve_alias(
        &self,
        alias: &MacroAlias,
        tokens: &proc_macro2::TokenStream,
        stack: &mut Vec<String>,
    ) -> Result<Option<Vec<ResolvedSourceEdge>>, String> {
        if alias.target == ["std", "include"] {
            let path =
                resolve_argument(&argument_template(tokens.clone()), &ArgumentTemplate::Empty)
                    .ok_or_else(|| "unsupported include alias argument".to_owned())?;
            return Ok(Some(vec![ResolvedSourceEdge::Include(path)]));
        }
        let (scope, name) = alias_target_scope(&alias.scope, &alias.target);
        if has_exact_local_symbol(self, &alias.source, &scope, &name, alias.source_position) {
            let resolved = self
                .resolve_named(
                    MacroSite {
                        source: &alias.source,
                        scope: &scope,
                        source_position: alias.source_position,
                        exact_scope: true,
                    },
                    &name,
                    tokens,
                    stack,
                )?
                .unwrap_or_else(|| panic!("unresolved macro alias target: {name}"));
            return Ok(Some(resolved));
        }
        if let Some(crate_name) = alias.target.first() {
            let exported = dependency_exported_definitions(self, &alias.source, crate_name, &name);
            match exported.as_slice() {
                [definition] => {
                    return Ok(Some(self.resolve_definition(definition, tokens, stack)?));
                }
                [] => {}
                _ => panic!("ambiguous exported macro {crate_name}::{name}"),
            }
        }
        let candidates = nearby_external_definitions(self, &alias.source, &name);
        if candidates.is_empty() {
            return Ok(None);
        }
        assert_eq!(
            candidates.len(),
            1,
            "ambiguous cross-file macro alias target: {name}"
        );
        Ok(Some(self.resolve_definition(
            candidates[0],
            tokens,
            stack,
        )?))
    }

    fn resolve_templates(
        &self,
        source: &Path,
        scope: &[String],
        templates: &[ExpansionTemplate],
        invocation: &ArgumentTemplate,
        source_position: u32,
        stack: &mut Vec<String>,
    ) -> Result<Vec<ResolvedSourceEdge>, String> {
        let mut edges = Vec::new();
        for template in templates {
            match template {
                ExpansionTemplate::Include(argument) => {
                    let path = resolve_argument(argument, invocation)
                        .unwrap_or_else(|| panic!("include macro omitted its source path"));
                    edges.push(ResolvedSourceEdge::Include(path));
                }
                ExpansionTemplate::Module {
                    name,
                    path,
                    test_only,
                } if !test_only => edges.push(ResolvedSourceEdge::Module {
                    name: name.clone(),
                    path: path.clone(),
                }),
                ExpansionTemplate::Module { .. } => {}
                ExpansionTemplate::Invoke { name, argument } => {
                    let nested = substitute_argument(argument, invocation);
                    let nested_tokens = argument_tokens(&nested);
                    if let Some(resolved) = self.resolve_named(
                        MacroSite {
                            source,
                            scope,
                            source_position,
                            exact_scope: false,
                        },
                        name,
                        &nested_tokens,
                        stack,
                    )? {
                        edges.extend(resolved);
                    } else {
                        assert!(
                            !argument_may_name_source(&nested),
                            "unresolved nested macro source edge through {name}"
                        );
                    }
                }
                ExpansionTemplate::Unsupported(reason) => return Err(reason.clone()),
            }
        }
        Ok(edges)
    }
}

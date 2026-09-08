use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use syn::visit::{self, Visit};

use crate::guard::inventory_macro_resolution::{
    MacroDefinition, MacroDefinitions, MacroInvocation,
};
use crate::guard::inventory_macro_rules::{MacroArm, macro_arms, selected_arm};
use crate::guard::inventory_macro_scope::{
    local_aliases, local_definitions, macro_path_scope, nearby_external_definitions,
    select_nearest_alias, select_nearest_definition,
};

pub(super) fn possible(
    closure: &HashSet<PathBuf>,
    macros: &MacroDefinitions,
    names: &HashSet<String>,
    glob: bool,
) -> bool {
    macros
        .invocations
        .iter()
        .filter(|site| closure.contains(&site.source))
        .any(|site| inspect(macros, site, names, glob, &mut HashSet::new()))
}

fn inspect(
    macros: &MacroDefinitions,
    site: &MacroInvocation,
    names: &HashSet<String>,
    glob: bool,
    stack: &mut HashSet<u32>,
) -> bool {
    match resolve(macros, site) {
        Resolution::Definition(definition) => {
            if !stack.insert(definition.ordinal) {
                return true;
            }
            let result = inspect_definition(macros, definition, &site.tokens, names, glob, stack);
            stack.remove(&definition.ordinal);
            result
        }
        Resolution::IncludeAlias => super::include_is_generated(&site.tokens.parse().unwrap()),
        Resolution::None => false,
    }
}

fn inspect_definition(
    macros: &MacroDefinitions,
    definition: &MacroDefinition,
    tokens: &str,
    names: &HashSet<String>,
    glob: bool,
    stack: &mut HashSet<u32>,
) -> bool {
    let tokens = tokens.parse().unwrap();
    let arm = selected_arm(&definition.arms, &tokens);
    let Ok(file) = syn::parse2::<syn::File>(arm.expansion_tokens.clone()) else {
        return true;
    };
    let mut generated = super::GeneratedSource {
        names,
        glob,
        found: false,
    };
    generated.visit_file(&file);
    if generated.found {
        return true;
    }
    let mut visitor = ExpansionVisitor {
        macros,
        source: &definition.source,
        scope: &definition.scope,
        position: definition.source_position,
        names,
        glob,
        stack,
        generated: HashMap::new(),
        found: false,
    };
    visitor.visit_file(&file);
    visitor.found
}

enum Resolution<'a> {
    Definition(&'a MacroDefinition),
    IncludeAlias,
    None,
}

fn resolve<'a>(macros: &'a MacroDefinitions, site: &MacroInvocation) -> Resolution<'a> {
    resolve_inner(macros, site, &mut HashSet::new())
}

fn resolve_inner<'a>(
    macros: &'a MacroDefinitions,
    site: &MacroInvocation,
    alias_stack: &mut HashSet<String>,
) -> Resolution<'a> {
    let path = syn::parse_str(&site.path.join("::")).unwrap();
    let Some((scope, name)) = macro_path_scope(&site.scope, &path) else {
        return Resolution::None;
    };
    let exact_scope = site.path.len() > 1;
    let definitions = local_definitions(
        macros,
        &site.source,
        &scope,
        &name,
        site.source_position,
        exact_scope,
    );
    if !definitions.is_empty() {
        return Resolution::Definition(select_nearest_definition(&definitions, &scope));
    }
    let candidates = local_aliases(
        macros,
        &site.source,
        &scope,
        &name,
        site.source_position,
        exact_scope,
    );
    if let Some(alias) = (!candidates.is_empty()).then(|| select_nearest_alias(&candidates)) {
        if alias.target == ["std", "include"] {
            return Resolution::IncludeAlias;
        }
        let key = format!("{}:{}", alias.source.display(), alias.target.join("::"));
        if !alias_stack.insert(key.clone()) {
            return Resolution::IncludeAlias;
        }
        let target = MacroInvocation {
            source: alias.source.clone(),
            scope: alias.scope.clone(),
            path: alias.target.clone(),
            tokens: site.tokens.clone(),
            source_position: alias.source_position,
        };
        let result = match resolve_inner(macros, &target, alias_stack) {
            Resolution::None => {
                let name = alias.target.last().expect("macro alias target is nonempty");
                let nearby = nearby_external_definitions(macros, &alias.source, name);
                match nearby.as_slice() {
                    [definition] => Resolution::Definition(definition),
                    _ => Resolution::None,
                }
            }
            result => result,
        };
        alias_stack.remove(&key);
        return result;
    }
    Resolution::None
}

struct ExpansionVisitor<'a> {
    macros: &'a MacroDefinitions,
    source: &'a PathBuf,
    scope: &'a [String],
    position: u32,
    names: &'a HashSet<String>,
    glob: bool,
    stack: &'a mut HashSet<u32>,
    generated: HashMap<String, Vec<MacroArm>>,
    found: bool,
}

impl<'ast> Visit<'ast> for ExpansionVisitor<'_> {
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.mac.path.is_ident("macro_rules") {
            if let Some(name) = &node.ident {
                self.generated
                    .insert(name.to_string(), macro_arms(node.mac.tokens.clone()));
            }
        } else {
            visit::visit_item_macro(self, node);
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.len() == 1
            && let Some(arms) = self.generated.get(&node.path.segments[0].ident.to_string())
        {
            let tokens = node.tokens.clone();
            let arm = selected_arm(arms, &tokens);
            let Ok(file) = syn::parse2::<syn::File>(arm.expansion_tokens.clone()) else {
                self.found = true;
                return;
            };
            let mut generated = super::GeneratedSource {
                names: self.names,
                glob: self.glob,
                found: false,
            };
            generated.visit_file(&file);
            self.found |= generated.found;
        }
        let site = MacroInvocation {
            source: self.source.clone(),
            scope: self.scope.to_vec(),
            path: node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
            tokens: node.tokens.to_string(),
            source_position: self.position,
        };
        self.found |= inspect(self.macros, &site, self.names, self.glob, self.stack);
        visit::visit_macro(self, node);
    }
}

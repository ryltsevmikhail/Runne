use std::collections::HashMap;
use std::path::PathBuf;

use super::MacroArm;

#[derive(Clone, Default)]
pub(in crate::guard) struct MacroDefinitions {
    pub(in crate::guard) items: HashMap<String, Vec<MacroDefinition>>,
    pub(in crate::guard) aliases: HashMap<String, Vec<MacroAlias>>,
    pub(in crate::guard) invocations: Vec<MacroInvocation>,
    pub(in crate::guard) dependencies:
        HashMap<(PathBuf, MacroDependencyKind, String), Vec<PathBuf>>,
    pub(in crate::guard) source_contexts: HashMap<PathBuf, Vec<MacroSourceContext>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::guard) enum MacroDependencyKind {
    Normal,
    Build,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::guard) struct MacroSourceContext {
    pub(in crate::guard) package_root: PathBuf,
    pub(in crate::guard) dependency_kind: MacroDependencyKind,
}

#[derive(Clone)]
pub(in crate::guard) struct MacroDefinition {
    pub(in crate::guard) ordinal: u32,
    pub(in crate::guard) exported: bool,
    pub(in crate::guard) source_position: u32,
    pub(in crate::guard) source: PathBuf,
    pub(in crate::guard) scope: Vec<String>,
    pub(in crate::guard) arms: Vec<MacroArm>,
}

#[derive(Clone)]
pub(in crate::guard) struct MacroAlias {
    pub(in crate::guard) source_position: u32,
    pub(in crate::guard) source: PathBuf,
    pub(in crate::guard) scope: Vec<String>,
    pub(in crate::guard) target: Vec<String>,
}

#[derive(Clone)]
pub(in crate::guard) struct MacroInvocation {
    pub(in crate::guard) source: PathBuf,
    pub(in crate::guard) scope: Vec<String>,
    pub(in crate::guard) path: Vec<String>,
    pub(in crate::guard) tokens: String,
    pub(in crate::guard) source_position: u32,
}

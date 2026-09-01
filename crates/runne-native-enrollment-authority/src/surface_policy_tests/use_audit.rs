#![cfg(test)]

use std::path::Path;

use syn::{Attribute, UseTree};

use super::{HANDOFF, PINNED, attribute_audit, normalized_ident, opaque_module, opaque_name};

pub(super) fn exact_public_reexports(
    tree: &UseTree,
    attributes: &[Attribute],
    source: &str,
) -> Result<Vec<&'static str>, String> {
    let mut bindings = Vec::new();
    collect_use_bindings(tree, &mut Vec::new(), &mut bindings);
    let mut names = Vec::new();
    for binding in bindings {
        let Some(name) = opaque_name(&binding.exposed) else {
            return Err(format!(
                "{source}: public re-export must originate exactly in its opaque module"
            ));
        };
        let exact = Path::new(source).file_name().and_then(|file| file.to_str()) == Some("lib.rs")
            && !binding.renamed
            && binding.origin == [opaque_module(name), name]
            && binding.exposed == name
            && if matches!(name, HANDOFF | PINNED) {
                attribute_audit::has_exact_macos_cfg(attributes)
            } else {
                !attribute_audit::has_cfg_or_path_substitution(attributes)
            };
        if !exact {
            return Err(format!(
                "{source}: public re-export must originate exactly in its opaque module"
            ));
        }
        names.push(name);
    }
    Ok(names)
}

struct UseBinding {
    origin: Vec<String>,
    exposed: String,
    renamed: bool,
}

fn collect_use_bindings(tree: &UseTree, prefix: &mut Vec<String>, output: &mut Vec<UseBinding>) {
    match tree {
        UseTree::Name(name) => {
            let ident = normalized_ident(&name.ident);
            let mut origin = prefix.clone();
            origin.push(ident.clone());
            output.push(UseBinding {
                origin,
                exposed: ident,
                renamed: false,
            });
        }
        UseTree::Rename(name) => {
            let mut origin = prefix.clone();
            origin.push(normalized_ident(&name.ident));
            output.push(UseBinding {
                origin,
                exposed: normalized_ident(&name.rename),
                renamed: true,
            });
        }
        UseTree::Path(path) => {
            prefix.push(normalized_ident(&path.ident));
            collect_use_bindings(&path.tree, prefix, output);
            prefix.pop();
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_bindings(item, prefix, output);
            }
        }
        UseTree::Glob(_) => output.push(UseBinding {
            origin: prefix.clone(),
            exposed: "*".to_owned(),
            renamed: false,
        }),
    }
}

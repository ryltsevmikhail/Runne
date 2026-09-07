use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::surface_syntax as syntax;

#[path = "signed_release_surface_macros.rs"]
mod macros;

pub fn load(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut loader = Loader::default();
    loader.load_file(&root.join("lib.rs"), root)?;
    loader.load_inc_superset(root)?;
    loader.output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(loader.output)
}

#[derive(Default)]
struct Loader {
    seen: HashSet<PathBuf>,
    output: Vec<(String, String)>,
}

impl Loader {
    fn load_file(&mut self, path: &Path, module_dir: &Path) -> Result<(), String> {
        let canonical = std::fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
        if !self.seen.insert(canonical.clone()) {
            return Ok(());
        }
        let contents = std::fs::read_to_string(&canonical)
            .map_err(|error| format!("cannot read {}: {error}", canonical.display()))?;
        let parsed = syn::parse_file(&contents)
            .map_err(|error| format!("cannot parse {}: {error}", canonical.display()))?;
        macros::reject_associated_macros(&parsed)
            .map_err(|error| format!("{error} in {}", canonical.display()))?;
        self.output
            .push((canonical.display().to_string(), contents));
        self.load_items(&parsed.items, &canonical, module_dir)
    }

    fn load_items(
        &mut self,
        items: &[syn::Item],
        source: &Path,
        module_dir: &Path,
    ) -> Result<(), String> {
        for item in items {
            match item {
                syn::Item::Mod(module) if !syntax::is_test_only(&module.attrs) => {
                    if let Some((_, items)) = &module.content {
                        self.load_items(items, source, &module_dir.join(module.ident.to_string()))?;
                    } else {
                        for target in module_paths(module, source, module_dir)? {
                            let child_dir = child_module_dir(&target)?;
                            self.load_file(&target, &child_dir)?;
                        }
                    }
                }
                syn::Item::Macro(item_macro) if !syntax::is_test_only(&item_macro.attrs) => {
                    self.load_macro_sources(item_macro, source, module_dir)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn load_macro_sources(
        &mut self,
        item: &syn::ItemMacro,
        source: &Path,
        module_dir: &Path,
    ) -> Result<(), String> {
        let parent = source
            .parent()
            .ok_or_else(|| format!("source has no parent: {}", source.display()))?;
        let candidates = macros::source_literals(item)
            .map_err(|error| format!("{error} in {}", source.display()))?;
        for candidate in candidates {
            let target = parent.join(&candidate);
            if target.is_file() {
                self.load_file(&target, module_dir)?;
            } else if item.ident.is_none() {
                return Err(format!(
                    "unresolved include candidate {candidate} in {}",
                    source.display()
                ));
            }
        }
        Ok(())
    }

    fn load_inc_superset(&mut self, directory: &Path) -> Result<(), String> {
        for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.is_dir() {
                self.load_inc_superset(&path)?;
            } else if path.extension().is_some_and(|extension| extension == "inc") {
                let module_dir = path
                    .parent()
                    .ok_or_else(|| format!("include has no parent: {}", path.display()))?;
                self.load_file(&path, module_dir)?;
            }
        }
        Ok(())
    }
}

fn module_paths(
    module: &syn::ItemMod,
    source: &Path,
    module_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let parent = source
        .parent()
        .ok_or_else(|| format!("module source has no parent: {}", source.display()))?;
    let mut targets = cfg_attr_paths(&module.attrs)?
        .into_iter()
        .map(|path| parent.join(path))
        .collect::<Vec<_>>();
    if let Some(path) = direct_path(&module.attrs)? {
        targets.push(parent.join(path));
        return Ok(targets);
    }
    let stem = module.ident.to_string();
    let flat = module_dir.join(format!("{stem}.rs"));
    let nested = module_dir.join(&stem).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, false) => targets.push(flat),
        (false, true) => targets.push(nested),
        (true, true) => {
            return Err(format!(
                "ambiguous module {stem} in {}",
                module_dir.display()
            ));
        }
        (false, false) if targets.is_empty() => {
            return Err(format!("missing module {stem} in {}", module_dir.display()));
        }
        (false, false) => {}
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn direct_path(attributes: &[syn::Attribute]) -> Result<Option<String>, String> {
    let Some(attribute) = attributes.iter().find(|attr| attr.path().is_ident("path")) else {
        return Ok(None);
    };
    path_meta(&attribute.meta)
}

fn cfg_attr_paths(attributes: &[syn::Attribute]) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg_attr"))
    {
        collect_generated_paths(&attribute.meta, &mut paths)?;
    }
    Ok(paths)
}

fn collect_generated_paths(meta: &syn::Meta, paths: &mut Vec<String>) -> Result<(), String> {
    if meta.path().is_ident("cfg_attr") {
        let syn::Meta::List(list) = meta else {
            return Err("unsupported cfg_attr form".into());
        };
        let arguments = list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .map_err(|error| format!("malformed cfg_attr: {error}"))?;
        let Some(condition) = arguments.first() else {
            return Err("empty cfg_attr".into());
        };
        if !syntax::meta_is_test_only(condition) {
            for attribute in arguments.iter().skip(1) {
                collect_generated_paths(attribute, paths)?;
            }
        }
    } else if let Some(path) = path_meta(meta)? {
        paths.push(path);
    }
    Ok(())
}

fn path_meta(meta: &syn::Meta) -> Result<Option<String>, String> {
    if !meta.path().is_ident("path") {
        return Ok(None);
    }
    let syn::Meta::NameValue(value) = meta else {
        return Err("unsupported path attribute".into());
    };
    let syn::Expr::Lit(expression) = &value.value else {
        return Err("non-literal path attribute".into());
    };
    let syn::Lit::Str(path) = &expression.lit else {
        return Err("non-string path attribute".into());
    };
    Ok(Some(path.value()))
}

fn child_module_dir(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("module has no parent: {}", path.display()))?;
    if path.file_name().is_some_and(|name| name == "mod.rs") {
        return Ok(parent.to_path_buf());
    }
    let stem = path
        .file_stem()
        .ok_or_else(|| format!("module has no stem: {}", path.display()))?;
    Ok(parent.join(stem))
}

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use syn::visit::{self, Visit};

#[derive(Default)]
struct Edges {
    paths: Vec<(PathBuf, bool)>,
    directory: PathBuf,
    attribute_directory: PathBuf,
    source_directory: PathBuf,
    test: bool,
}

impl<'ast> Visit<'ast> for Edges {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Fn(value) => value.attrs.as_slice(),
            syn::Item::Mod(value) => value.attrs.as_slice(),
            syn::Item::Impl(value) => value.attrs.as_slice(),
            syn::Item::Macro(value) => value.attrs.as_slice(),
            _ => &[],
        };
        let previous = self.test;
        self.test |= super::test_only(attrs);
        visit::visit_item(self, item);
        self.test = previous;
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let path = module.attrs.iter().find_map(|attr| {
            if attr.path().is_ident("path")
                && let syn::Meta::NameValue(value) = &attr.meta
                && let syn::Expr::Lit(value) = &value.value
                && let syn::Lit::Str(value) = &value.lit
            {
                return Some(value.value());
            }
            None
        });
        if let Some((_, items)) = &module.content {
            let directory = path.map_or_else(
                || self.directory.join(module.ident.to_string()),
                |path| self.attribute_directory.join(path),
            );
            let old_directory = std::mem::replace(&mut self.directory, directory.clone());
            let old_attribute = std::mem::replace(&mut self.attribute_directory, directory);
            for item in items {
                self.visit_item(item);
            }
            self.directory = old_directory;
            self.attribute_directory = old_attribute;
        } else if let Some(path) = path {
            self.add(&self.attribute_directory.join(path));
        } else {
            let path = self.directory.join(module.ident.to_string());
            self.add(&path.with_extension("rs"));
            self.add(&path.join("mod.rs"));
        }
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if value.path.is_ident("include")
            && let Ok(path) = syn::parse2::<syn::LitStr>(value.tokens.clone())
        {
            self.add(&self.source_directory.join(path.value()));
        }
        visit::visit_macro(self, value);
    }
}

impl Edges {
    fn add(&mut self, path: &Path) {
        if path.is_file() {
            self.paths.push((path.canonicalize().unwrap(), self.test));
        }
    }
}

fn collect(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path.canonicalize().unwrap());
        }
    }
}

/// Excludes only files reachable exclusively through explicit cfg(test) module/include edges.
/// Unknown cfgs, orphan files, test-like names and shared production paths stay audited.
pub fn sources(root: &Path, files: &mut Vec<PathBuf>) {
    let mut all = Vec::new();
    collect(root, &mut all);
    let mut graph = BTreeMap::new();
    let mut children = BTreeSet::new();
    for path in &all {
        let parent = path.parent().unwrap();
        let stem = path.file_stem().unwrap();
        let directory = if ["lib", "main", "mod"].iter().any(|name| stem == *name) {
            parent.to_owned()
        } else {
            parent.join(stem)
        };
        let mut edges = Edges {
            directory,
            attribute_directory: parent.to_owned(),
            source_directory: parent.to_owned(),
            ..Default::default()
        };
        if let Ok(file) = syn::parse_file(&fs::read_to_string(path).unwrap()) {
            edges.test = super::test_only(&file.attrs);
            edges.visit_file(&file);
        }
        children.extend(edges.paths.iter().map(|(path, _)| path.clone()));
        graph.insert(path.clone(), edges.paths);
    }
    let mut visited = BTreeSet::new();
    let mut pending = all
        .iter()
        .filter(|path| {
            !children.contains(*path)
                || path
                    .file_name()
                    .is_some_and(|name| name == "lib.rs" || name == "main.rs")
        })
        .map(|path| (path.clone(), false))
        .collect::<Vec<_>>();
    while let Some((path, test)) = pending.pop() {
        if !visited.insert((path.clone(), test)) {
            continue;
        }
        if let Some(edges) = graph.get(&path) {
            pending.extend(
                edges
                    .iter()
                    .map(|(child, own_test)| (child.clone(), test || *own_test)),
            );
        }
    }
    files.extend(all.into_iter().filter(|path| {
        !visited.contains(&(path.clone(), true)) || visited.contains(&(path.clone(), false))
    }));
}
